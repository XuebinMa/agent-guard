//! Structured recognition of direct Git outbound update intent.
//!
//! Policy rules historically matched the raw shell string, so equivalent
//! invocations such as `/usr/bin/git push`, `env git push`, or
//! `git -C repo push` did not share a decision. This module parses command
//! positions recovered by the shell grammar, unwraps transparent launchers,
//! and emits a small canonical policy subject for both porcelain `push` and
//! plumbing-level `send-pack` updates. When an unmodeled outer command contains
//! adjacent standalone Git argv tokens, the module also emits a conservative
//! candidate without claiming that the outer program will execute them.

use super::ast::{environment_writes, parse_shell, ShellParse};
use super::tokenize::shell_split;
use super::wrappers::{command_name, unwrap_command_wrappers};

/// Alias expansion and alias shell snippets are followed at most this deep.
/// Git refuses an alias loop; a chain this long is treated as an unmodeled
/// push rather than silently dropped.
const MAX_ALIAS_DEPTH: usize = 8;

/// How strongly the shell syntax establishes that the Git argv will execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitPushDetection {
    /// Git is the resolved command after modeled wrapper layers are removed.
    ModeledExecution,
    /// Git appears as an argv suffix of an unmodeled outer command. This is
    /// conservative evidence only; arbitrary program semantics are unknowable
    /// from argv, so audit records must not describe it as exact execution.
    EmbeddedArgv {
        outer_command: String,
        argument_index: usize,
    },
}

/// The security-relevant parts of a modeled Git outbound update or a
/// conservative embedded argv candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPushIntent {
    /// Actual command family observed in the shell program. Policy subjects
    /// intentionally normalize both values to `git push`, while audit previews
    /// retain whether the agent invoked porcelain or plumbing directly.
    pub command: &'static str,
    /// Ordered `git -C` directory changes. Relative entries are interpreted
    /// from the directory established by the preceding entry.
    pub directory_changes: Vec<String>,
    /// Explicit Git metadata directory supplied through `--git-dir`.
    pub git_dir: Option<String>,
    /// Explicit work tree supplied through `--work-tree`.
    pub work_tree: Option<String>,
    /// Remote/repository operand supplied to `git push` or `git send-pack`.
    pub remote: Option<String>,
    /// Refspec operands, retained so callers can display the requested scope.
    pub refspecs: Vec<String>,
    pub force: bool,
    pub force_with_lease: bool,
    pub force_if_includes: bool,
    pub mirror: bool,
    pub delete: bool,
    pub detection: GitPushDetection,
}

impl GitPushIntent {
    /// Canonical command strings used only for policy matching.
    ///
    /// The ordinary subject is always present so a single `prefix: "git push"`
    /// rule covers every recognised spelling. Destructive forms add a stable
    /// subject so deny rules win even when the flag appeared after the remote,
    /// in a short-option bundle, or implicitly in a refspec.
    pub fn policy_subjects(&self) -> Vec<&'static str> {
        let mut subjects = Vec::with_capacity(5);
        if self.force_with_lease {
            subjects.push("git push --force-with-lease");
        }
        if self.force {
            subjects.push("git push --force");
        }
        if self.mirror {
            subjects.push("git push --mirror");
        }
        if self.delete {
            subjects.push("git push --delete");
        }
        subjects.push("git push");
        subjects
    }
}

/// Recover modeled Git outbound updates plus conservative embedded argv
/// candidates from a shell program.
///
/// Push semantics can also come from configuration. Command-line config
/// (`git -c`, `--config-env`, aliases defined there) and the `GIT_CONFIG_*`
/// environment are visible in the command and are modeled here. Repository and
/// user config files are not: an agent that can edit them can change what a
/// plain `git push` does, which is why the broker, not this recognizer, is the
/// outbound boundary.
pub fn git_push_intents(command: &str) -> Result<Vec<GitPushIntent>, String> {
    git_push_intents_at_depth(command, &[], 0)
}

fn git_push_intents_at_depth(
    command: &str,
    inherited: &[ConfigEntry],
    depth: usize,
) -> Result<Vec<GitPushIntent>, String> {
    let commands = match parse_shell(command) {
        ShellParse::Understood(commands) => commands,
        ShellParse::TooComplex(reason) => return Err(reason),
    };
    let environment_config = environment_writes(command)
        .iter()
        .any(|write| injects_git_config(&write.name));

    let mut intents = Vec::new();
    for resolved in &commands {
        let argv = unwrap_command_wrappers(&resolved.argv);
        let wrapper_config = resolved.argv[..resolved.argv.len() - argv.len()]
            .iter()
            .any(|token| {
                token
                    .split_once('=')
                    .is_some_and(|(name, _)| injects_git_config(name))
            });
        let unknown_config = environment_config || wrapper_config;

        let direct = parse_git_push(argv, inherited, depth);
        if !direct.is_empty() {
            for mut intent in direct {
                if unknown_config {
                    assume_config_changes_semantics(&mut intent);
                }
                intents.push(intent);
            }
            continue;
        }

        let Some(outer_command) = argv.first().map(|token| command_name(token).to_string()) else {
            continue;
        };
        for argument_index in 1..argv.len() {
            let candidate = command_name(&argv[argument_index]);
            if !matches!(candidate, "git" | "git-push" | "git-send-pack") {
                continue;
            }
            for mut intent in parse_git_push(&argv[argument_index..], inherited, depth) {
                intent.detection = GitPushDetection::EmbeddedArgv {
                    outer_command: outer_command.clone(),
                    argument_index,
                };
                if unknown_config {
                    assume_config_changes_semantics(&mut intent);
                }
                intents.push(intent);
            }
        }
    }
    Ok(intents)
}

/// One `name=value` pair from Git's command-line config.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigEntry {
    /// Lowercased section, e.g. `remote`.
    section: String,
    /// Subsection as written (Git compares it case-sensitively), e.g. `origin`.
    subsection: Option<String>,
    /// Lowercased variable name, e.g. `push`.
    variable: String,
    /// `None` when the value comes from somewhere this command does not show,
    /// such as `--config-env`.
    value: Option<String>,
}

impl ConfigEntry {
    fn parse(key: &str, value: Option<String>) -> Option<Self> {
        let (section, rest) = key.split_once('.')?;
        let (subsection, variable) = match rest.rsplit_once('.') {
            Some((subsection, variable)) => (Some(subsection.to_string()), variable),
            None => (None, rest),
        };
        Some(Self {
            section: section.to_ascii_lowercase(),
            subsection,
            variable: variable.to_ascii_lowercase(),
            value,
        })
    }

    /// `-c key=value`; a bare `-c key` sets a boolean to true.
    fn from_assignment(assignment: &str) -> Option<Self> {
        match assignment.split_once('=') {
            Some((key, value)) => Self::parse(key, Some(value.to_string())),
            None => Self::parse(assignment, Some("true".to_string())),
        }
    }

    /// `--config-env=key=ENVVAR`: the value lives in the environment.
    fn from_config_env(assignment: &str) -> Option<Self> {
        let (key, _) = assignment.split_once('=')?;
        Self::parse(key, None)
    }

    fn is_false(&self) -> bool {
        self.value.as_deref().is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "false" | "no" | "off" | "0" | ""
            )
        })
    }
}

/// Environment variables that inject Git configuration whose contents a
/// command line does not show in a form this module models.
fn injects_git_config(name: &str) -> bool {
    matches!(
        name,
        "GIT_CONFIG_PARAMETERS"
            | "GIT_CONFIG_COUNT"
            | "GIT_CONFIG"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_SYSTEM"
    ) || name.starts_with("GIT_CONFIG_KEY_")
        || name.starts_with("GIT_CONFIG_VALUE_")
}

/// Config the command injects but this module cannot read may turn an
/// ordinary push into any destructive one, so it is classified as all of them.
fn assume_config_changes_semantics(intent: &mut GitPushIntent) {
    intent.force = true;
    intent.mirror = true;
    intent.delete = true;
}

/// Apply command-line config that changes what a push does.
///
/// `remote.<name>.mirror` makes the push a mirror, and `remote.<name>.push`
/// supplies refspecs as if they were typed: `+` forces and a leading `:`
/// removes. The remote name is not compared, so config for any remote counts.
fn apply_push_config(mut intent: GitPushIntent, config: &[ConfigEntry]) -> GitPushIntent {
    for entry in config {
        if entry.section != "remote" || entry.subsection.is_none() {
            continue;
        }
        match entry.variable.as_str() {
            "mirror" if !entry.is_false() => intent.mirror = true,
            "push" => match entry.value.as_deref() {
                Some(refspec) => {
                    intent.force |= refspec.starts_with('+');
                    intent.delete |= refspec.starts_with(':');
                }
                None => {
                    intent.force = true;
                    intent.delete = true;
                }
            },
            _ => {}
        }
    }
    intent
}

/// A push this module could not model, e.g. an alias whose definition is not
/// visible. Classified as every destructive form so no rule is relaxed by it.
fn unmodeled_push(outer_command: &str, argument_index: usize) -> GitPushIntent {
    GitPushIntent {
        command: "git push",
        directory_changes: Vec::new(),
        git_dir: None,
        work_tree: None,
        remote: None,
        refspecs: Vec::new(),
        force: true,
        force_with_lease: false,
        force_if_includes: false,
        mirror: true,
        delete: true,
        detection: GitPushDetection::EmbeddedArgv {
            outer_command: outer_command.to_string(),
            argument_index,
        },
    }
}

fn parse_git_push(argv: &[String], inherited: &[ConfigEntry], depth: usize) -> Vec<GitPushIntent> {
    let argv = unwrap_command_wrappers(argv);
    let Some(first) = argv.first() else {
        return Vec::new();
    };
    let executable = command_name(first);

    if executable == "git-push" {
        let intent = parse_push_args(&argv[1..], "git push", Vec::new(), None, None);
        return vec![apply_push_config(intent, inherited)];
    }
    if executable == "git-send-pack" {
        let intent = parse_send_pack_args(&argv[1..], Vec::new(), None, None);
        return vec![apply_push_config(intent, inherited)];
    }
    if executable != "git" {
        return Vec::new();
    }

    let mut config = inherited.to_vec();
    let mut directory_changes = Vec::new();
    let mut git_dir = None;
    let mut work_tree = None;
    let mut index = 1;
    while index < argv.len() {
        let token = argv[index].as_str();
        if token == "--" {
            index += 1;
            break;
        }

        if token == "-C" {
            let Some(value) = argv.get(index + 1) else {
                return Vec::new();
            };
            directory_changes.push(value.clone());
            index += 2;
            continue;
        }
        if token == "--git-dir" {
            let Some(value) = argv.get(index + 1) else {
                return Vec::new();
            };
            git_dir = Some(value.clone());
            index += 2;
            continue;
        }
        if token == "--work-tree" {
            let Some(value) = argv.get(index + 1) else {
                return Vec::new();
            };
            work_tree = Some(value.clone());
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("-C") {
            if !value.is_empty() {
                directory_changes.push(value.to_string());
                index += 1;
                continue;
            }
        }
        if let Some(value) = token.strip_prefix("--git-dir=") {
            git_dir = Some(value.to_string());
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--work-tree=") {
            work_tree = Some(value.to_string());
            index += 1;
            continue;
        }

        if matches!(token, "-c" | "--config-env" | "--namespace") {
            let Some(value) = argv.get(index + 1) else {
                return Vec::new();
            };
            let entry = match token {
                "-c" => ConfigEntry::from_assignment(value),
                "--config-env" => ConfigEntry::from_config_env(value),
                _ => None,
            };
            config.extend(entry);
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--config-env=") {
            config.extend(ConfigEntry::from_config_env(value));
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("-c") {
            config.extend(ConfigEntry::from_assignment(value));
            index += 1;
            continue;
        }
        if token.starts_with("--namespace=") || token.starts_with("--exec-path=") {
            index += 1;
            continue;
        }
        if token == "--exec-path" {
            // `--exec-path` may be a query with no value. Preserve a following
            // literal outbound subcommand; otherwise consume the path.
            if argv
                .get(index + 1)
                .is_some_and(|next| next != "push" && next != "send-pack")
            {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if token.starts_with('-') {
            // Remaining global switches are boolean. Unknown switches make Git
            // fail, but skipping them keeps a later literal `push` visible.
            index += 1;
            continue;
        }
        break;
    }

    match argv.get(index).map(String::as_str) {
        Some("push") => vec![apply_push_config(
            parse_push_args(
                &argv[index + 1..],
                "git push",
                directory_changes,
                git_dir,
                work_tree,
            ),
            &config,
        )],
        Some("send-pack") => vec![apply_push_config(
            parse_send_pack_args(&argv[index + 1..], directory_changes, git_dir, work_tree),
            &config,
        )],
        Some(subcommand) => expand_alias(argv, index, subcommand, &config, depth),
        None => Vec::new(),
    }
}

/// Follow a command-line alias (`git -c alias.p=push p`) to what it runs.
///
/// Only aliases defined on this command line are visible. A plain alias is
/// spliced in place of its name, as Git does. A `!` alias is a shell snippet
/// that receives the remaining arguments; it is parsed as a shell program and
/// inherits the command-line config, which Git exports to it.
fn expand_alias(
    argv: &[String],
    index: usize,
    subcommand: &str,
    config: &[ConfigEntry],
    depth: usize,
) -> Vec<GitPushIntent> {
    let Some(alias) = config.iter().rev().find(|entry| {
        entry.section == "alias"
            && entry.subsection.is_none()
            && entry.variable.eq_ignore_ascii_case(subcommand)
    }) else {
        return Vec::new();
    };
    if depth >= MAX_ALIAS_DEPTH {
        return vec![unmodeled_push("git", index)];
    }
    let Some(definition) = alias.value.as_deref() else {
        return vec![unmodeled_push("git", index)];
    };

    if let Some(snippet) = definition.strip_prefix('!') {
        let mut program = snippet.to_string();
        for argument in &argv[index + 1..] {
            program.push_str(" '");
            program.push_str(&argument.replace('\'', r"'\''"));
            program.push('\'');
        }
        return match git_push_intents_at_depth(&program, config, depth + 1) {
            Ok(intents) => intents
                .into_iter()
                .map(|mut intent| {
                    intent.detection = GitPushDetection::EmbeddedArgv {
                        outer_command: "git".to_string(),
                        argument_index: index,
                    };
                    intent
                })
                .collect(),
            Err(_) => vec![unmodeled_push("git", index)],
        };
    }

    let mut expanded = argv[..index].to_vec();
    expanded.extend(shell_split(definition));
    expanded.extend(argv[index + 1..].iter().cloned());
    parse_git_push(&expanded, &[], depth + 1)
}

/// Git's option parser accepts any unambiguous prefix of a long option, so
/// `--mirr` is `--mirror`. Matching only the full spelling let an abbreviated
/// destructive flag classify as an ordinary push. Any prefix counts here: a
/// prefix Git finds ambiguous makes it refuse the command, so over-matching
/// cannot hide a push.
fn abbreviates(token: &str, option: &str) -> bool {
    token
        .strip_prefix("--")
        .map(|name| name.split_once('=').map_or(name, |(name, _)| name))
        .is_some_and(|name| !name.is_empty() && option.starts_with(name))
}

fn parse_push_args(
    args: &[String],
    command: &'static str,
    directory_changes: Vec<String>,
    git_dir: Option<String>,
    work_tree: Option<String>,
) -> GitPushIntent {
    let mut explicit_force = false;
    let mut force_with_lease = false;
    let mut force_if_includes = false;
    let mut mirror = false;
    let mut delete = false;
    let mut option_remote = None;
    let mut operands = Vec::new();
    let mut end_of_options = false;

    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if end_of_options {
            operands.push(token.to_string());
            index += 1;
            continue;
        }
        if token == "--" {
            end_of_options = true;
            index += 1;
            continue;
        }
        if matches!(
            token,
            "--repo" | "--receive-pack" | "--exec" | "--push-option" | "--server-option" | "-o"
        ) {
            if index + 1 < args.len() && token == "--repo" {
                option_remote = Some(args[index + 1].clone());
            }
            index += 2;
            continue;
        }
        if let Some(remote) = token.strip_prefix("--repo=") {
            option_remote = Some(remote.to_string());
            index += 1;
            continue;
        }

        match token {
            "--force-with-lease" => force_with_lease = true,
            "--no-force-with-lease" => force_with_lease = false,
            "--force-if-includes" => force_if_includes = true,
            "--no-force-if-includes" => force_if_includes = false,
            "--force" => explicit_force = true,
            "--no-force" => explicit_force = false,
            "--mirror" => mirror = true,
            "--no-mirror" => mirror = false,
            "--delete" => delete = true,
            _ if abbreviates(token, "force-with-lease") => force_with_lease = true,
            _ if abbreviates(token, "force") => explicit_force = true,
            _ if abbreviates(token, "mirror") => mirror = true,
            // `--prune` removes every remote ref the refspecs no longer name,
            // which is the same effect as an explicit removal.
            _ if abbreviates(token, "delete") || abbreviates(token, "prune") => delete = true,
            _ if short_option_contains(token, 'f') => explicit_force = true,
            _ if short_option_contains(token, 'd') => delete = true,
            _ if !token.starts_with('-') => operands.push(token.to_string()),
            _ => {}
        }
        index += 1;
    }

    // `--repo=<repository>` is equivalent to the positional repository. Git's
    // positional operand wins when both are present; remaining operands are
    // refspecs. Keeping that precedence is essential for an honest preview.
    let (remote, refspecs) = if operands.is_empty() {
        (option_remote, Vec::new())
    } else {
        let mut operands = operands.into_iter();
        (operands.next(), operands.collect())
    };
    let forced_refspec = refspecs.iter().any(|value| value.starts_with('+'));
    delete |= refspecs.iter().any(|value| value.starts_with(':'));
    let force = explicit_force || force_with_lease || forced_refspec;

    GitPushIntent {
        command,
        directory_changes,
        git_dir,
        work_tree,
        remote,
        refspecs,
        force,
        force_with_lease,
        force_if_includes,
        mirror,
        delete,
        detection: GitPushDetection::ModeledExecution,
    }
}

fn parse_send_pack_args(
    args: &[String],
    directory_changes: Vec<String>,
    git_dir: Option<String>,
    work_tree: Option<String>,
) -> GitPushIntent {
    let mut explicit_force = false;
    let mut force_with_lease = false;
    let mut force_if_includes = false;
    let mut mirror = false;
    let mut operands = Vec::new();
    let mut end_of_options = false;

    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if end_of_options {
            operands.push(token.to_string());
            index += 1;
            continue;
        }
        if token == "--" {
            end_of_options = true;
            index += 1;
            continue;
        }

        if matches!(
            token,
            "--receive-pack" | "--exec" | "--remote" | "--push-option"
        ) {
            index += 2;
            continue;
        }
        if token.starts_with("--receive-pack=")
            || token.starts_with("--exec=")
            || token.starts_with("--remote=")
            || token.starts_with("--push-option=")
        {
            index += 1;
            continue;
        }

        match token {
            "--force-with-lease" => force_with_lease = true,
            "--no-force-with-lease" => force_with_lease = false,
            "--force-if-includes" => force_if_includes = true,
            "--no-force-if-includes" => force_if_includes = false,
            "--force" => explicit_force = true,
            "--no-force" => explicit_force = false,
            "--mirror" => mirror = true,
            "--no-mirror" => mirror = false,
            _ if abbreviates(token, "force-with-lease") => force_with_lease = true,
            _ if abbreviates(token, "force") => explicit_force = true,
            _ if abbreviates(token, "mirror") => mirror = true,
            _ if short_option_contains(token, 'f') => explicit_force = true,
            _ if !token.starts_with('-') => operands.push(token.to_string()),
            _ => {}
        }
        index += 1;
    }

    let mut operands = operands.into_iter();
    let remote = operands.next();
    let refspecs: Vec<String> = operands.collect();
    let forced_refspec = refspecs.iter().any(|value| value.starts_with('+'));
    let delete = refspecs.iter().any(|value| value.starts_with(':'));
    let force = explicit_force || force_with_lease || forced_refspec;

    GitPushIntent {
        command: "git send-pack",
        directory_changes,
        git_dir,
        work_tree,
        remote,
        refspecs,
        force,
        force_with_lease,
        force_if_includes,
        mirror,
        delete,
        detection: GitPushDetection::ModeledExecution,
    }
}

fn short_option_contains(token: &str, wanted: char) -> bool {
    token.starts_with('-')
        && !token.starts_with("--")
        && token.len() > 1
        && token.chars().skip(1).any(|flag| flag == wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_equivalent_push_entry_points() {
        for command in [
            "/usr/bin/git push origin main",
            "env git push origin main",
            "command git push origin main",
            "stdbuf -o0 git push origin main",
            "setsid -fw git push origin main",
            r#""git" push origin main"#,
            r#"g""it push origin main"#,
            r#"g\it push origin main"#,
            "git -C /workspace push origin main",
            "git --git-dir=/workspace/.git push origin main",
            "git-push origin main",
            "{ git push origin main; }",
        ] {
            let intents = git_push_intents(command).expect("valid shell");
            assert_eq!(intents.len(), 1, "push missing from {command:?}");
            assert!(intents[0].policy_subjects().contains(&"git push"));
        }
    }

    #[test]
    fn classifies_destructive_push_semantics() {
        let cases = [
            ("git push -f origin main", "git push --force"),
            (
                "git -C repo push origin main --force-with-lease",
                "git push --force-with-lease",
            ),
            ("git push origin +main:main", "git push --force"),
            ("git push origin :main", "git push --delete"),
            ("git push --delete origin main", "git push --delete"),
            ("git push --mirror origin", "git push --mirror"),
        ];

        for (command, subject) in cases {
            let intents = git_push_intents(command).expect("valid shell");
            assert!(
                intents[0].policy_subjects().contains(&subject),
                "{command:?} did not produce {subject:?}: {:?}",
                intents[0]
            );
        }
    }

    #[test]
    fn retains_repository_remote_and_refspec_scope() {
        let intent = git_push_intents(
            "git -C /workspace --git-dir=.git --work-tree=src push origin main:main tag:v1",
        )
        .expect("valid shell")
        .pop()
        .expect("push intent");

        assert_eq!(intent.directory_changes, ["/workspace"]);
        assert_eq!(intent.git_dir.as_deref(), Some(".git"));
        assert_eq!(intent.work_tree.as_deref(), Some("src"));
        assert_eq!(intent.remote.as_deref(), Some("origin"));
        assert_eq!(intent.refspecs, ["main:main", "tag:v1"]);
    }

    #[test]
    fn positional_repository_overrides_repo_option_like_git() {
        let intent = git_push_intents("git push --repo=origin backup main")
            .expect("valid shell")
            .pop()
            .expect("push intent");

        assert_eq!(intent.remote.as_deref(), Some("backup"));
        assert_eq!(intent.refspecs, ["main"]);
    }

    #[test]
    fn force_if_includes_alone_is_not_a_forced_push() {
        let intent = git_push_intents("git push --force-if-includes origin main")
            .expect("valid shell")
            .pop()
            .expect("push intent");

        assert!(intent.force_if_includes);
        assert!(!intent.force_with_lease);
        assert!(!intent.force);
        assert!(!intent.policy_subjects().contains(&"git push --force"));
    }

    #[test]
    fn recognizes_send_pack_as_the_same_outbound_boundary() {
        for command in [
            "git send-pack origin main",
            "git-send-pack origin main",
            "git -C repo send-pack origin main",
            "git --exec-path send-pack origin main",
        ] {
            let intents = git_push_intents(command).expect("valid shell");
            assert_eq!(intents.len(), 1, "send-pack missing from {command:?}");
            assert!(intents[0].policy_subjects().contains(&"git push"));
        }

        for command in [
            "git send-pack --force origin main",
            "git-send-pack -f origin main",
            "git send-pack --force-with-lease origin main",
            "git send-pack --mirror origin",
            "git send-pack origin +main:main",
        ] {
            let intents = git_push_intents(command).expect("valid shell");
            assert_eq!(intents.len(), 1, "send-pack missing from {command:?}");
            assert!(
                intents[0].policy_subjects().contains(&"git push --force")
                    || intents[0].policy_subjects().contains(&"git push --mirror"),
                "destructive send-pack was not canonicalized: {command:?}"
            );
        }
    }

    #[test]
    fn conservatively_recognizes_git_intent_after_unknown_prefix_tokens() {
        for command in [
            "firejail --quiet git push origin main",
            "bwrap --ro-bind / / git push origin main",
            "torsocks git-send-pack origin main",
            "flatpak-spawn --host /usr/bin/git send-pack origin main",
            r#"probe "git" "push" origin main"#,
        ] {
            let intents = git_push_intents(command).expect("valid shell");
            assert_eq!(
                intents.len(),
                1,
                "embedded Git intent missing from {command:?}"
            );
            assert!(intents[0].policy_subjects().contains(&"git push"));
            assert!(matches!(
                intents[0].detection,
                GitPushDetection::EmbeddedArgv { .. }
            ));
        }

        for command in [
            "firejail git push --force origin main",
            "cpulimit -l 50 -- git push origin +main:main",
            "ssh-agent git-send-pack --mirror origin",
            "echo git push --force origin main",
            "probe git status git push --force origin main",
        ] {
            let intents = git_push_intents(command).expect("valid shell");
            assert_eq!(
                intents.len(),
                1,
                "embedded Git intent missing from {command:?}"
            );
            assert!(
                intents[0].force || intents[0].mirror,
                "destructive strength was lost for {command:?}: {:?}",
                intents[0]
            );
        }
    }

    fn single_intent(command: &str) -> GitPushIntent {
        let mut intents = git_push_intents(command).expect("valid shell");
        assert_eq!(intents.len(), 1, "expected one intent for {command:?}");
        intents.pop().expect("one intent")
    }

    /// Git accepts any unambiguous prefix of a long option. A recognizer that
    /// only matched full spellings classified abbreviated destructive flags as
    /// an ordinary push.
    #[test]
    fn abbreviated_destructive_options_keep_their_meaning() {
        for (command, subject) in [
            ("git push --mirr origin", "git push --mirror"),
            (
                "git push --force-w origin main",
                "git push --force-with-lease",
            ),
            (
                "git push --force-w=main:abc origin main",
                "git push --force-with-lease",
            ),
            ("git push --del origin main", "git push --delete"),
            ("git send-pack --mirr origin", "git push --mirror"),
            (
                "git send-pack --force-w origin main",
                "git push --force-with-lease",
            ),
        ] {
            let intent = single_intent(command);
            assert!(
                intent.policy_subjects().contains(&subject),
                "{command:?} must produce {subject:?}: {intent:?}"
            );
        }
    }

    #[test]
    fn prune_is_classified_as_remote_ref_removal() {
        for command in [
            "git push --prune origin refs/heads/*:refs/heads/*",
            "git push --pru origin refs/heads/*:refs/heads/*",
        ] {
            let intent = single_intent(command);
            assert!(intent.delete, "{command:?} removes remote refs: {intent:?}");
            assert!(intent.policy_subjects().contains(&"git push --delete"));
        }
    }

    #[test]
    fn non_destructive_long_options_stay_ordinary() {
        for command in [
            "git push --force-if-includes origin main",
            "git push --dry-run origin main",
            "git push --porcelain origin main",
            "git push --follow-tags origin main",
            "git push --no-prune origin main",
        ] {
            assert_eq!(
                single_intent(command).policy_subjects(),
                vec!["git push"],
                "{command:?} is an ordinary push"
            );
        }
    }

    /// Command-line config can make a plain-looking push destructive.
    #[test]
    fn command_line_config_that_changes_push_semantics_is_modeled() {
        let mirror = single_intent("git -c remote.origin.mirror=true push origin");
        assert!(mirror.mirror, "{mirror:?}");

        let forced =
            single_intent("git -c remote.origin.push=+refs/heads/main:refs/heads/main push origin");
        assert!(forced.force, "{forced:?}");

        let removal = single_intent("git -c remote.origin.push=:refs/heads/main push origin");
        assert!(removal.delete, "{removal:?}");

        let from_env = single_intent("git --config-env=remote.origin.push=REFSPEC push origin");
        assert!(from_env.force && from_env.delete, "{from_env:?}");

        let disabled = single_intent("git -c remote.origin.mirror=false push origin main");
        assert!(
            !disabled.mirror,
            "an explicit false is not a mirror: {disabled:?}"
        );

        let unrelated = single_intent("git -c user.name=agent push origin main");
        assert_eq!(unrelated.policy_subjects(), vec!["git push"]);
    }

    #[test]
    fn config_injected_through_the_environment_is_assumed_destructive() {
        for command in [
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=k GIT_CONFIG_VALUE_0=v git push origin main",
            "env GIT_CONFIG_PARAMETERS=x git push origin main",
            "export GIT_CONFIG_GLOBAL=/tmp/cfg; git push origin main",
        ] {
            let intent = single_intent(command);
            assert!(
                intent.force && intent.mirror && intent.delete,
                "{command:?} injects config this module cannot read: {intent:?}"
            );
        }
    }

    /// An alias defined on the command line hid the push from recognition.
    #[test]
    fn command_line_aliases_are_followed_to_the_push() {
        let plain = single_intent("git -c alias.p=push p --force origin main");
        assert!(plain.force, "{plain:?}");
        assert_eq!(plain.remote.as_deref(), Some("origin"));

        let options_in_alias = single_intent("git -c 'alias.p=push --mirror' p origin");
        assert!(options_in_alias.mirror, "{options_in_alias:?}");

        let shell = single_intent("git -c 'alias.p=!git push' p origin main");
        assert!(shell.policy_subjects().contains(&"git push"));
        assert!(matches!(
            shell.detection,
            GitPushDetection::EmbeddedArgv { .. }
        ));

        let shell_config =
            single_intent("git -c remote.origin.mirror=true -c 'alias.p=!git push' p origin");
        assert!(shell_config.mirror, "{shell_config:?}");

        let looping = single_intent("git -c alias.p=p p origin main");
        assert!(
            looping.force && looping.mirror && looping.delete,
            "{looping:?}"
        );

        assert!(
            git_push_intents("git -c alias.st=status st")
                .expect("valid shell")
                .is_empty(),
            "an alias for a non-outbound command is not a push"
        );
    }

    #[test]
    fn quoted_git_push_text_is_not_an_executable_intent() {
        for command in [
            "grep -r 'git push --force' src",
            "echo 'git push origin main'",
        ] {
            assert!(
                git_push_intents(command).expect("valid shell").is_empty(),
                "one quoted data token must not become executable Git intent: {command:?}"
            );
        }
        assert!(
            git_push_intents("echo git status")
                .expect("valid shell")
                .is_empty(),
            "non-outbound Git words must not become a push intent"
        );
    }
}
