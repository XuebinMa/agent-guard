//! Path and write/read-target extraction plus workspace-escape checks.

use std::path::{Component, Path, PathBuf};

use super::ast::{parse_shell, ShellParse};
use super::tables::{
    READ_PATH_REDIRECTIONS, STATE_MODIFYING_COMMANDS, WRITE_COMMANDS, WRITE_REDIRECTIONS,
};
use super::tokenize::shell_split;
use super::types::{PermissionMode, ValidationResult};
use super::wrappers::{command_name, leads_with_target_hiding_spawner, unwrap_command_wrappers};

/// Relative parent-escape sentinel emitted when a target-hiding spawner
/// (`find -exec` / `xargs`) wraps a write command. `validate_paths` rejects
/// `../` escapes regardless of the policy escape list, so this cannot be
/// allow-listed away — the right posture when the real target is unverifiable.
const UNVERIFIABLE_WRAPPER_TARGET: &str = "../agent-guard-unverifiable-wrapper-write-target";

/// What an extracted operand is, so a refusal can name it correctly.
///
/// A link source is neither written nor read by `ln`; it is checked because
/// the link binds a name inside the workspace to it. Reporting it as a write
/// target reads as a misparse of the command, and a reader who believes the
/// check misparsed their command goes looking for a way around it rather than
/// at what it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Write,
    Read,
    LinkSource,
}

impl TargetKind {
    fn describe(self) -> &'static str {
        match self {
            TargetKind::Write => "write target",
            TargetKind::Read => "read target",
            TargetKind::LinkSource => "link source",
        }
    }
}

fn as_writes(targets: Vec<String>) -> Vec<(String, TargetKind)> {
    targets
        .into_iter()
        .map(|target| (target, TargetKind::Write))
        .collect()
}

pub fn validate_paths(
    command: &str,
    mode: PermissionMode,
    workspace: &Path,
    escape_paths: &[String],
) -> ValidationResult {
    if !matches!(
        mode,
        PermissionMode::ReadOnly | PermissionMode::WorkspaceWrite
    ) {
        return ValidationResult::Allow;
    }

    let workspace = normalize_path(workspace);

    for (target, kind) in collect_write_targets(command) {
        if let Some(block) = check_target(&target, kind, &workspace, escape_paths) {
            return block;
        }
    }

    for target in collect_read_targets(command) {
        if let Some(block) = check_target(&target, TargetKind::Read, &workspace, escape_paths) {
            return block;
        }
    }

    ValidationResult::Allow
}

/// Verify one extracted target against the workspace boundary.
///
/// Returns `Some(Block)` when the target may not be touched, `None` when it is
/// inside the workspace or is not a path this gate governs.
fn check_target(
    target: &str,
    kind: TargetKind,
    workspace: &Path,
    escape_paths: &[String],
) -> Option<ValidationResult> {
    let kind_name = kind.describe();
    let candidate = target.trim_matches(|c| c == '"' || c == '\'');
    if candidate.is_empty() || candidate == "/dev/null" {
        return None;
    }

    if candidate.contains('$')
        || candidate.contains('`')
        || candidate.starts_with('~')
        || may_expand_to_parent_component(candidate)
    {
        return Some(ValidationResult::Block {
            reason: format!(
                "{kind_name} '{candidate}' cannot be resolved without ambient shell expansion"
            ),
        });
    }

    let path = Path::new(candidate);

    if path.is_absolute() {
        // The policy-declared escape list is stated in absolute terms, so it
        // stands on its own and is consulted before the workspace comparison.
        if matches_escape_glob(candidate, escape_paths) {
            return None;
        }

        // A workspace root that does not normalise to an absolute path yields
        // no containment boundary at all: `Path::starts_with` against the
        // empty prefix left by `.` (or by an absent working directory) is
        // vacuously true, which silently accepts every absolute target. An
        // unverifiable bound must fail closed, not degrade to "unrestricted".
        if !workspace.is_absolute() {
            return Some(ValidationResult::Block {
                reason: format!(
                    "{kind_name} '{candidate}' cannot be verified: no absolute workspace root is configured"
                ),
            });
        }

        if !path_stays_within_workspace(path, workspace)
            || existing_path_resolves_outside(path, workspace)
        {
            let mut reason =
                format!("{kind_name} '{candidate}' is outside the configured workspace");
            if kind == TargetKind::LinkSource {
                // Without this the refusal states a fact the reader has to
                // guess the significance of: the operand is not being written,
                // the link that would point at it is.
                reason.push_str(
                    ": a later write through the link would land there; add it to \
                     workspace_escape_paths if that location is meant to be reachable",
                );
            }
            return Some(ValidationResult::Block { reason });
        }

        return None;
    }

    // Relative `../` escape is always suspicious regardless of policy, so it
    // is never rescued by the escape list — so no escape-list hint here.
    if has_parent_dir_escape(path) {
        return Some(ValidationResult::Block {
            reason: format!("{kind_name} '{candidate}' escapes the configured workspace"),
        });
    }

    if existing_path_resolves_outside(&workspace.join(path), workspace) {
        return Some(ValidationResult::Block {
            reason: format!(
                "{kind_name} '{candidate}' resolves through a link outside the configured workspace"
            ),
        });
    }

    None
}

/// Whether shell expansion could rewrite this target's components after the
/// lexical checks below have accepted it.
///
/// Brace expansion turns `/ws/.{.,.}/x` into `/ws/../x`, and a pathname glob
/// such as `.?` or `.*` matches `..` under shells that do not skip dot entries
/// (dash, which is `sh` on Debian and Ubuntu). Neither spelling contains a
/// literal `..` component, so without this a target could resolve outside the
/// workspace after validation.
fn may_expand_to_parent_component(candidate: &str) -> bool {
    has_brace_expansion(candidate)
        || candidate
            .split(['/', '\\'])
            .any(glob_component_can_match_parent)
}

/// `{a,b}` or `{x..y}`. Quoted braces are already unquoted in the target, so
/// a literal `{a,b}` filename is refused too; that over-match is deliberate.
pub(super) fn has_brace_expansion(candidate: &str) -> bool {
    let mut rest = candidate;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return false;
        };
        let body = &after[..close];
        if body.contains(',') || body.contains("..") {
            return true;
        }
        rest = after;
    }
    false
}

fn glob_component_can_match_parent(component: &str) -> bool {
    if !component.contains(['*', '?', '[']) {
        return false;
    }
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        // Shells only match a leading dot literally, so `*` never matches
        // `..` but `.*` and `.?` do.
        require_literal_leading_dot: true,
    };
    glob::Pattern::new(component).map_or(true, |pattern| pattern.matches_with("..", options))
}

fn matches_escape_glob(candidate: &str, escape_paths: &[String]) -> bool {
    escape_paths.iter().any(|pat| {
        glob::Pattern::new(pat)
            .map(|g| g.matches(candidate))
            .unwrap_or(false)
    })
}

pub fn validate_sed(command: &str, mode: PermissionMode) -> ValidationResult {
    if matches!(
        mode,
        PermissionMode::ReadOnly | PermissionMode::WorkspaceWrite
    ) {
        for argv in resolved_argvs(command) {
            let argv = unwrap_command_wrappers(&argv);
            let Some(name) = argv.first() else {
                continue;
            };
            if command_name(name) != "sed" {
                continue;
            }
            match super::sed::parse(&argv[1..]) {
                Ok(invocation) if mode == PermissionMode::ReadOnly && invocation.in_place => {
                    return ValidationResult::Block {
                        reason: "Sed in-place editing is not allowed in read-only mode".to_string(),
                    };
                }
                Err(reason) => {
                    return ValidationResult::Block {
                        reason: reason.to_string(),
                    }
                }
                Ok(_) => {}
            }
        }
    }
    ValidationResult::Allow
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn has_parent_dir_escape(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn path_stays_within_workspace(path: &Path, workspace: &Path) -> bool {
    let normalized_path = normalize_path(path);
    normalized_path == workspace || normalized_path.starts_with(workspace)
}

/// Resolve the nearest existing ancestor when both it and the workspace can be
/// canonicalized. This catches an existing symlink component even when the
/// final file does not exist yet. A nonexistent synthetic workspace (used by
/// callers that only need lexical checks) cannot support this extra signal.
fn existing_path_resolves_outside(path: &Path, workspace: &Path) -> bool {
    let Ok(real_workspace) = workspace.canonicalize() else {
        return false;
    };
    let mut ancestor = path;
    loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = ancestor.parent() else {
                    return true;
                };
                ancestor = parent;
            }
            Err(_) => return true,
        }
    }
    ancestor
        .canonicalize()
        .map_or(true, |resolved| !resolved.starts_with(real_workspace))
}

fn collect_write_targets(command: &str) -> Vec<(String, TargetKind)> {
    let mut targets = flat_segments(command)
        .iter()
        .flat_map(|segment| write_targets_for_segment(segment))
        .collect::<Vec<_>>();
    targets.extend(
        resolved_argvs(command)
            .iter()
            .flat_map(|argv| write_targets_for_segment(argv)),
    );
    targets
}

/// Segments produced by the legacy flat split.
///
/// Redirection operators are literal tokens wherever they appear, so this pass
/// still sees `>` / `>>` / `<` targets inside a grouping construct that the
/// command-word logic could not reach. It is kept as the redirection sweep;
/// [`resolved_argvs`] supplies the command positions.
fn flat_segments(command: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut current = Vec::new();
    for token in shell_split(command) {
        if matches!(token.as_str(), "|" | "||" | "&&" | ";" | "&") {
            segments.push(std::mem::take(&mut current));
            continue;
        }
        current.push(token);
    }
    segments.push(current);
    segments
}

/// Command positions recovered from the grammar.
///
/// Returns nothing when the input does not parse; `validate_bash_command`
/// rejects that case up front, so an unparseable command never reaches a
/// decision through this path.
fn resolved_argvs(command: &str) -> Vec<Vec<String>> {
    match parse_shell(command) {
        ShellParse::Understood(commands) => {
            commands.into_iter().map(|resolved| resolved.argv).collect()
        }
        ShellParse::TooComplex(_) => Vec::new(),
    }
}

fn write_targets_for_segment(segment: &[String]) -> Vec<(String, TargetKind)> {
    if segment.is_empty() {
        return Vec::new();
    }

    let original = segment;
    // Strip transparent wrappers (`sudo`/`env`/…) and `NAME=value` prefixes so
    // the real command word and its write operands are what we reason about
    // (e.g. `sudo -u root rm /etc/passwd`, `env FOO=1 tee /etc/passwd`).
    let segment = unwrap_command_wrappers(segment);

    // Fail closed for `find -exec` / `xargs` wrapping a write/state command:
    // the operand comes from the traversal or stdin, so the visible token
    // (`{}`, or nothing) is not the real target. Emit the unverifiable sentinel
    // so the path gate blocks rather than trusting a placeholder. Issue #55.
    if leads_with_target_hiding_spawner(original) {
        if let Some(cmd) = segment.first().map(|s| command_name(s.as_str())) {
            if WRITE_COMMANDS.contains(&cmd) || STATE_MODIFYING_COMMANDS.contains(&cmd) {
                return vec![(UNVERIFIABLE_WRAPPER_TARGET.to_string(), TargetKind::Write)];
            }
        }
    }

    let mut targets: Vec<String> = Vec::new();
    // `ln`/`link` sources: checked like a write target, reported as what they
    // are. Kept apart from `targets` so only this one operand class changes.
    let mut link_sources: Vec<String> = Vec::new();

    // Pass 1: collect redirection targets. A redirection (`>`, `>>`, `>&`) can
    // appear ANYWHERE in a simple command — before the command word
    // (`>out cmd`), in the middle (`cmd >out arg`), or after it. Scanning the
    // whole segment (not just the tokens after the command word) closes the
    // leading-redirection bypass where `>/etc/passwd echo x` was parsed with
    // `>` as the command word, so the out-of-workspace target was never seen.
    // Redirection operators and their targets are removed from the positional
    // stream so the command-word detection below is robust to a leading
    // redirect.
    let mut positional: Vec<&String> = Vec::new();
    let mut expecting_redirection_target = false;
    for token in segment {
        if WRITE_REDIRECTIONS.contains(&token.as_str()) {
            expecting_redirection_target = true;
            continue;
        }
        if expecting_redirection_target {
            expecting_redirection_target = false;
            if !token.starts_with('&') {
                targets.push(token.clone());
            }
            continue;
        }
        positional.push(token);
    }

    // Pass 2: command-specific write operands. The command word is the first
    // positional token (redirections/targets already stripped above).
    let Some(command) = positional.first().map(|token| command_name(token.as_str())) else {
        return as_writes(targets);
    };
    let args = &positional[1..];

    match command {
        "touch" | "mkdir" | "rmdir" | "rm" | "chmod" | "chown" | "chgrp" | "unlink" | "tee" => {
            targets.extend(
                args.iter()
                    .filter(|token| !token.starts_with('-'))
                    .map(|token| token.to_string()),
            );
        }
        "truncate" => targets.extend(truncate_write_targets(args)),
        "sed" => {
            let args: Vec<String> = args.iter().map(|arg| (*arg).clone()).collect();
            match super::sed::parse(&args) {
                Ok(invocation) if invocation.in_place => targets.extend(invocation.files),
                Ok(_) => {}
                Err(_) => targets.push(UNVERIFIABLE_WRAPPER_TARGET.to_string()),
            }
        }
        "mv" | "cp" | "install" => {
            // GNU coreutils `-t DEST` / `--target-directory=DEST` write into DEST,
            // not the trailing positional — closes the `cp -t /etc/cron.d payload`
            // confinement bypass where the real destination was never checked.
            // Without that flag the destination is the last non-flag arg (the
            // arg-taking flags `-m MODE`/`-S SUFFIX`/`-o OWNER` sit mid-line, so
            // the trailing token is the real target for cp/mv/install alike).
            if let Some(dest) = target_directory_flag(args) {
                targets.push(dest);
            } else if let Some(last) = args.iter().rev().find(|token| !token.starts_with('-')) {
                targets.push(last.to_string());
            }
        }
        "ln" | "link" => {
            // Both `ln -s` (symlink) and `ln` / `link` (hardlink) bind the
            // created name to the source: symlinks follow the source for
            // future writes, hardlinks share its inode. So the source is
            // checked as well as the link name — a workspace-internal link
            // whose source points outside is the first half of the 2026-05-14
            // HIGH path-traversal-escape finding, and refusing it is the
            // point of this arm.
            //
            // The two operands are separated only so each is reported as what
            // it is. `ln -s A B` writes B and aliases A; with `-t DIR` every
            // positional is a source, and a lone `A` creates its basename in
            // the cwd, so A is a source there too.
            let positional: Vec<String> = args
                .iter()
                .filter(|token| !token.starts_with('-'))
                .map(|token| token.to_string())
                .collect();

            if let Some(directory) = target_directory_flag(args) {
                link_sources.extend(positional);
                targets.push(directory);
            } else if let Some((link_name, sources)) = positional.split_last() {
                if sources.is_empty() {
                    link_sources.push(link_name.clone());
                } else {
                    link_sources.extend(sources.iter().cloned());
                    targets.push(link_name.clone());
                }
            }
        }
        "dd" => {
            // `dd` writes to its `of=PATH` operand (reading from `if=` or, when
            // absent, from stdin). The path is an `=`-joined operand, not a
            // redirection or positional arg, so it is invisible to both scans
            // above — closes the `dd of=/etc/passwd` bypass.
            for token in args {
                if let Some(path) = token.strip_prefix("of=") {
                    if !path.is_empty() {
                        targets.push(path.to_string());
                    }
                }
            }
        }
        "tar" => targets.extend(tar_write_targets(args)),
        "unzip" => targets.extend(option_values(args, &['d'], &[])),
        "sort" => targets.extend(option_values(args, &['o'], &["output"])),
        "curl" => targets.extend(option_values(args, &['o'], &["output", "output-dir"])),
        "wget" => targets.extend(option_values(
            args,
            &['O', 'P'],
            &["output-document", "directory-prefix"],
        )),
        "rsync" => targets.extend(last_local_operand(args, RSYNC_VALUE_OPTIONS)),
        "scp" => targets.extend(last_local_operand(args, SCP_VALUE_OPTIONS)),
        "git" => targets.extend(git_checkout_destinations(args)),
        "find" => targets.extend(find_write_targets(args)),
        _ => {}
    }

    let mut extracted = as_writes(targets);
    extracted.extend(
        link_sources
            .into_iter()
            .map(|source| (source, TargetKind::LinkSource)),
    );
    extracted
}

/// Extract the destination from GNU coreutils target-directory flags
/// (`cp`/`mv`/`install` accept `-t DEST` and `--target-directory[=]DEST`).
///
/// Returns the first destination found, or `None` when no such flag is present
/// (the caller then falls back to the trailing positional). Recognises:
/// `--target-directory=DEST`, `--target-directory DEST`, `-tDEST` (glued),
/// `-t DEST`, and short-flag bundles ending in `t` (e.g. `-vt DEST`).
fn target_directory_flag(args: &[&String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let s = arg.as_str();
        if let Some(rest) = s.strip_prefix("--target-directory=") {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        } else if s == "--target-directory" {
            if let Some(dest) = iter.next() {
                return Some(dest.to_string());
            }
        } else if let Some(rest) = s.strip_prefix("-t") {
            // `-tDEST` glued vs `-t` taking the next arg.
            if rest.is_empty() {
                if let Some(dest) = iter.next() {
                    return Some(dest.to_string());
                }
            } else {
                return Some(rest.to_string());
            }
        } else if s.len() > 1 && s.starts_with('-') && !s.starts_with("--") && s.ends_with('t') {
            // Short-flag bundle whose last char is `t` (e.g. `cp -vt DEST`):
            // the destination is the following argument.
            if let Some(dest) = iter.next() {
                return Some(dest.to_string());
            }
        }
    }
    None
}

/// Values of the named options in the spellings `-x VALUE`, `-xVALUE`, a short
/// bundle ending in `x` followed by VALUE, `--long VALUE` and `--long=VALUE`.
///
/// The first matching letter in a bundle is taken as the option, so an earlier
/// letter's attached value can be misread as a destination. That over-matches
/// toward refusal, never toward a missed sink.
fn option_values(args: &[&String], short: &[char], long: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let token = arg.as_str();
        if token == "--" {
            break;
        }
        let attached = if let Some(name) = token.strip_prefix("--") {
            match name.split_once('=') {
                Some((name, value)) if long.contains(&name) => Some(value),
                None if long.contains(&name) => Some(""),
                _ => continue,
            }
        } else if let Some(bundle) = token.strip_prefix('-') {
            match bundle.char_indices().find(|(_, flag)| short.contains(flag)) {
                Some((at, flag)) => Some(&bundle[at + flag.len_utf8()..]),
                None => continue,
            }
        } else {
            continue;
        };
        match attached {
            Some("") => values.extend(iter.next().map(|value| value.to_string())),
            Some(value) => values.push(value.to_string()),
            None => {}
        }
    }
    values
}

/// Options of `rsync` / `scp` that take a separate value, so that value is not
/// mistaken for the trailing destination operand.
const RSYNC_VALUE_OPTIONS: (&[char], &[&str]) = (
    &['e', 'f', 'B', 'T', 'M'],
    &[
        "rsh",
        "exclude",
        "exclude-from",
        "include",
        "include-from",
        "filter",
        "files-from",
        "log-file",
        "log-file-format",
        "password-file",
        "port",
        "block-size",
        "temp-dir",
        "partial-dir",
        "backup-dir",
        "suffix",
        "compare-dest",
        "copy-dest",
        "link-dest",
        "max-size",
        "min-size",
        "bwlimit",
        "timeout",
        "contimeout",
        "chmod",
        "chown",
        "out-format",
        "rsync-path",
        "remote-option",
        "write-batch",
        "only-write-batch",
        "read-batch",
    ],
);
const SCP_VALUE_OPTIONS: (&[char], &[&str]) =
    (&['c', 'D', 'F', 'i', 'J', 'l', 'o', 'P', 'S', 'X'], &[]);

/// The destination of a copy whose last operand is where it writes, unless
/// that operand names a remote host (`host:path`, `scheme://…`).
fn last_local_operand(args: &[&String], value_options: (&[char], &[&str])) -> Option<String> {
    let (short, long) = value_options;
    let mut operands = Vec::new();
    let mut options_done = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let token = arg.as_str();
        if options_done || !token.starts_with('-') || token == "-" {
            operands.push(token);
        } else if token == "--" {
            options_done = true;
        } else if let Some(name) = token.strip_prefix("--") {
            if long.contains(&name) {
                iter.next();
            }
        } else {
            // The first value-taking flag ends a short bundle. Any remaining
            // characters are its attached value, not more flags: `-Ttempf`
            // must not interpret the value's final `f` as another option and
            // consume the destination that follows it.
            let mut flags = token.chars().skip(1).peekable();
            while let Some(flag) = flags.next() {
                if short.contains(&flag) {
                    if flags.peek().is_none() {
                        iter.next();
                    }
                    break;
                }
            }
        }
    }
    let destination = operands.last()?;
    let remote = destination.contains("://")
        || destination
            .split_once(':')
            .is_some_and(|(host, _)| !host.contains('/'));
    (!remote).then(|| destination.to_string())
}

/// Where `git worktree add`, `git clone` and `git init` create a checkout, and
/// the file a subcommand writes its `--output` to,
/// resolved against any `git -C <dir>` given before the subcommand.
///
/// Other subcommands also write under `-C`; this covers the ones whose own
/// operand names a new directory.
fn git_checkout_destinations(args: &[&String]) -> Vec<String> {
    let mut base: Option<PathBuf> = None;
    let mut index = 0;
    while let Some(token) = args.get(index).map(|arg| arg.as_str()) {
        if token == "-C" {
            let Some(directory) = args.get(index + 1) else {
                return Vec::new();
            };
            base = Some(base.map_or_else(|| PathBuf::from(directory), |b| b.join(directory)));
            index += 2;
        } else if matches!(
            token,
            "-c" | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--config-env"
                | "--attr-source"
                | "--shallow-file"
        ) {
            index += 2;
        } else if token.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }

    let under_base = |path: String| match &base {
        Some(base) if !Path::new(&path).is_absolute() => {
            base.join(path).to_string_lossy().into_owned()
        }
        _ => path,
    };
    // `--output <file>` (log, diff, show, …) writes that file.
    let output_files = |args| option_values(args, &[], &["output"]);

    let rest = &args[index.min(args.len())..];
    let (value_short, value_long, operand, rest): (&[char], &[&str], usize, _) =
        match rest.first().map(|arg| arg.as_str()) {
            Some("worktree") if rest.get(1).is_some_and(|arg| arg.as_str() == "add") => {
                (&['b', 'B'], &["reason"], 0, &rest[2..])
            }
            Some("clone") => (
                &['b', 'o', 'u', 'j', 'c'],
                &[
                    "branch",
                    "origin",
                    "upload-pack",
                    "reference",
                    "reference-if-able",
                    "depth",
                    "shallow-since",
                    "shallow-exclude",
                    "jobs",
                    "filter",
                    "config",
                    "template",
                    "server-option",
                    "bundle-uri",
                    "revision",
                ],
                1,
                &rest[1..],
            ),
            Some("init") => (
                &['b'],
                &["template", "initial-branch", "object-format", "ref-format"],
                0,
                &rest[1..],
            ),
            // `git archive -o FILE` is the short form of its `--output`.
            Some("archive") => {
                return option_values(rest, &['o'], &["output"])
                    .into_iter()
                    .map(under_base)
                    .collect()
            }
            _ => return output_files(rest).into_iter().map(under_base).collect(),
        };

    let mut destinations = option_values(rest, &[], &["separate-git-dir"]);
    let mut operands = Vec::new();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        let token = arg.as_str();
        if !token.starts_with('-') {
            operands.push(token);
        } else if token == "--separate-git-dir"
            || token
                .strip_prefix("--")
                .is_some_and(|name| value_long.contains(&name))
            || (!token.starts_with("--")
                && token
                    .chars()
                    .last()
                    .is_some_and(|flag| value_short.contains(&flag)))
        {
            iter.next();
        }
    }
    // With no directory operand the checkout lands in the `-C` directory.
    destinations.push(operands.get(operand).map_or(".", |path| path).to_string());

    destinations.into_iter().map(under_base).collect()
}

/// What a `find` invocation writes: the starting points it walks when it has
/// `-delete`, and the file named after `-fprint`, `-fprint0`, `-fprintf` or
/// `-fls`. `find -exec` is unwrapped to its child before this is reached.
fn find_write_targets(args: &[&String]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut iter = args.iter().map(|arg| arg.as_str()).peekable();
    // Leading options, then starting points up to the first expression word.
    let mut roots = Vec::new();
    while let Some(token) = iter.peek().copied() {
        if matches!(token, "-H" | "-L" | "-P") || token.starts_with("-O") {
            iter.next();
        } else if token == "-D" {
            iter.next();
            iter.next();
        } else if token.starts_with('-') || matches!(token, "(" | "!" | ",") {
            break;
        } else {
            roots.push(token.to_string());
            iter.next();
        }
    }
    let mut deletes = false;
    while let Some(token) = iter.next() {
        match token {
            "-delete" => deletes = true,
            "-fprint" | "-fprint0" | "-fprintf" | "-fls" => {
                targets.extend(iter.next().map(str::to_string));
            }
            _ => {}
        }
    }
    if deletes {
        if roots.is_empty() {
            roots.push(".".to_string());
        }
        targets.extend(roots);
    }
    targets
}

/// Extract paths that `tar` writes: the archive for create/append/update modes,
/// and every explicit `-C` / `--directory` destination for extract mode.
///
/// Handles the common forms: short bundles (`-cf`, `-czf`), the old dashless
/// first-arg bundle (`tar czf out.tar .`), and the long options
/// (`--create`, `--file=out.tar`, `--file out.tar`) plus the common short and
/// long extraction-directory spellings.
fn tar_write_targets(args: &[&String]) -> Vec<String> {
    let mut is_write_mode = false;
    let mut is_extract_mode = false;
    let mut archive: Option<String> = None;
    let mut expect_file = false;
    let mut expect_directory = false;
    let mut extraction_directories = Vec::new();

    for (index, token) in args.iter().enumerate() {
        let t = token.as_str();
        if expect_directory {
            extraction_directories.push(t.to_string());
            expect_directory = false;
            continue;
        }
        if expect_file {
            archive = Some(t.to_string());
            expect_file = false;
            continue;
        }
        if let Some(rest) = t.strip_prefix("--file=") {
            archive = Some(rest.to_string());
            continue;
        }
        if let Some(rest) = t.strip_prefix("--directory=") {
            if !rest.is_empty() {
                extraction_directories.push(rest.to_string());
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix("-C") {
            if !rest.is_empty() {
                extraction_directories.push(rest.to_string());
                continue;
            }
        }
        match t {
            "--file" => expect_file = true,
            "--directory" => expect_directory = true,
            "--extract" | "--get" => is_extract_mode = true,
            "--create" | "--append" | "--update" | "--catenate" | "--concatenate" => {
                is_write_mode = true;
            }
            _ if t.starts_with("--") => {}
            _ => {
                // Short flag bundle: `-cf` (dashed) or, only as the first arg,
                // the old dashless form `czf`. tar's contract is that `f` must
                // be the last flag char for the following token to be the
                // archive path.
                let flags = if let Some(stripped) = t.strip_prefix('-') {
                    Some(stripped)
                } else if index == 0 {
                    Some(t)
                } else {
                    None
                };
                if let Some(flags) = flags {
                    if flags.chars().any(|c| matches!(c, 'c' | 'r' | 'u' | 'A')) {
                        is_write_mode = true;
                    }
                    if flags.ends_with('f') {
                        expect_file = true;
                    }
                    if flags.chars().any(|c| c == 'x') {
                        is_extract_mode = true;
                    }
                    if flags.ends_with('C') {
                        expect_directory = true;
                    }
                }
            }
        }
    }

    let mut targets = Vec::new();
    if let Some(path) = archive {
        if is_write_mode && !path.is_empty() && path != "-" {
            targets.push(path);
        }
    }
    if is_extract_mode {
        targets.extend(extraction_directories);
    }
    targets
}

fn truncate_write_targets(args: &[&String]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut skip_option_value = false;
    let mut options_done = false;
    for argument in args {
        let value = argument.as_str();
        if skip_option_value {
            skip_option_value = false;
            continue;
        }
        if !options_done && value == "--" {
            options_done = true;
            continue;
        }
        if !options_done && matches!(value, "-s" | "--size" | "-r" | "--reference") {
            skip_option_value = true;
            continue;
        }
        if !options_done
            && (value.starts_with("--size=")
                || value.starts_with("--reference=")
                || (value.starts_with("-s") && value.len() > 2)
                || (value.starts_with("-r") && value.len() > 2))
        {
            continue;
        }
        if !options_done && value.starts_with('-') {
            continue;
        }
        targets.push(value.to_string());
    }
    targets
}

fn collect_read_targets(command: &str) -> Vec<String> {
    let mut targets = flat_segments(command)
        .iter()
        .flat_map(|segment| read_targets_for_segment(segment))
        .collect::<Vec<_>>();
    targets.extend(
        resolved_argvs(command)
            .iter()
            .flat_map(|argv| read_targets_for_segment(argv)),
    );
    targets
}

fn read_targets_for_segment(segment: &[String]) -> Vec<String> {
    if segment.is_empty() {
        return Vec::new();
    }

    // Unwrap one leading `sudo` layer, then scan the WHOLE segment for `<`
    // redirections. As with write redirections, an input redirect can precede
    // the command word (`</etc/shadow cat`); scanning only the tokens after
    // the command word missed that form.
    let segment = if segment.first().is_some_and(|token| token == "sudo") && segment.len() > 1 {
        &segment[1..]
    } else {
        segment
    };

    let mut targets = Vec::new();

    // Only explicit `<` redirections are treated as path targets.
    // `<<` (here-doc) and `<<<` (here-string) are tokenized as single tokens
    // by `shell_split`, so an exact-match on `READ_PATH_REDIRECTIONS` (just
    // `<`) naturally excludes them. We do not infer read targets from
    // positional args (e.g. `cat /etc/shadow`) — that is out of scope and
    // covered by the `read_file` tool path with deny lists.
    let mut expecting_redirection_target = false;
    for token in segment {
        if READ_PATH_REDIRECTIONS.contains(&token.as_str()) {
            expecting_redirection_target = true;
            continue;
        }

        if expecting_redirection_target {
            expecting_redirection_target = false;
            if !token.starts_with('&') {
                targets.push(token.clone());
            }
        }
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy_destination(args: &[&str], options: (&[char], &[&str])) -> Option<String> {
        let owned: Vec<String> = args.iter().map(|value| (*value).to_string()).collect();
        let borrowed: Vec<&String> = owned.iter().collect();
        last_local_operand(&borrowed, options)
    }

    #[test]
    fn attached_short_copy_option_values_do_not_consume_the_destination() {
        for args in [
            &["source", "-Ttempf", "/outside/destination"][..],
            &["source", "-aTtempf", "/outside/destination"][..],
            &["source", "-ersyncf", "/outside/destination"][..],
        ] {
            assert_eq!(
                copy_destination(args, RSYNC_VALUE_OPTIONS).as_deref(),
                Some("/outside/destination"),
                "the attached option value swallowed the destination: {args:?}"
            );
        }
        for args in [
            &["source", "-Fconfigi", "/outside/destination"][..],
            &["source", "-voUser=personP", "/outside/destination"][..],
        ] {
            assert_eq!(
                copy_destination(args, SCP_VALUE_OPTIONS).as_deref(),
                Some("/outside/destination"),
                "the attached option value swallowed the destination: {args:?}"
            );
        }
    }

    #[test]
    fn separate_short_copy_option_values_and_remote_destinations_still_parse() {
        for args in [
            &["source", "-T", "tempf", "/workspace/destination"][..],
            &["source", "-aT", "tempf", "/workspace/destination"][..],
            &["source", "--temp-dir", "tempf", "/workspace/destination"][..],
        ] {
            assert_eq!(
                copy_destination(args, RSYNC_VALUE_OPTIONS).as_deref(),
                Some("/workspace/destination")
            );
        }
        assert_eq!(
            copy_destination(
                &["source", "-vF", "configi", "/workspace/destination"],
                SCP_VALUE_OPTIONS
            )
            .as_deref(),
            Some("/workspace/destination")
        );
        assert!(copy_destination(
            &["source", "-Ttempf", "backup@host.invalid:destination"],
            RSYNC_VALUE_OPTIONS
        )
        .is_none());
    }
}
