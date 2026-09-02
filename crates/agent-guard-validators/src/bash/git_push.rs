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

use super::ast::{parse_shell, ShellParse};
use super::wrappers::{command_name, unwrap_command_wrappers};

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
pub fn git_push_intents(command: &str) -> Result<Vec<GitPushIntent>, String> {
    let commands = match parse_shell(command) {
        ShellParse::Understood(commands) => commands,
        ShellParse::TooComplex(reason) => return Err(reason),
    };

    let mut intents = Vec::new();
    for resolved in &commands {
        let argv = unwrap_command_wrappers(&resolved.argv);
        if let Some(intent) = parse_git_push(argv) {
            intents.push(intent);
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
            if let Some(mut intent) = parse_git_push(&argv[argument_index..]) {
                intent.detection = GitPushDetection::EmbeddedArgv {
                    outer_command: outer_command.clone(),
                    argument_index,
                };
                intents.push(intent);
            }
        }
    }
    Ok(intents)
}

fn parse_git_push(argv: &[String]) -> Option<GitPushIntent> {
    let argv = unwrap_command_wrappers(argv);
    let executable = command_name(argv.first()?);

    if executable == "git-push" {
        return Some(parse_push_args(
            &argv[1..],
            "git push",
            Vec::new(),
            None,
            None,
        ));
    }
    if executable == "git-send-pack" {
        return Some(parse_send_pack_args(&argv[1..], Vec::new(), None, None));
    }
    if executable != "git" {
        return None;
    }

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
            let value = argv.get(index + 1)?.clone();
            directory_changes.push(value);
            index += 2;
            continue;
        }
        if token == "--git-dir" {
            git_dir = Some(argv.get(index + 1)?.clone());
            index += 2;
            continue;
        }
        if token == "--work-tree" {
            work_tree = Some(argv.get(index + 1)?.clone());
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
            argv.get(index + 1)?;
            index += 2;
            continue;
        }
        if token.starts_with("-c")
            || token.starts_with("--config-env=")
            || token.starts_with("--namespace=")
            || token.starts_with("--exec-path=")
        {
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
        Some("push") => Some(parse_push_args(
            &argv[index + 1..],
            "git push",
            directory_changes,
            git_dir,
            work_tree,
        )),
        Some("send-pack") => Some(parse_send_pack_args(
            &argv[index + 1..],
            directory_changes,
            git_dir,
            work_tree,
        )),
        _ => None,
    }
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
            _ if token.starts_with("--force-with-lease=") => force_with_lease = true,
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
            _ if token.starts_with("--force-with-lease=") => force_with_lease = true,
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
