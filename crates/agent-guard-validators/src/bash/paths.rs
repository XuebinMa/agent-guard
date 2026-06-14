//! Path and write/read-target extraction plus workspace-escape checks.

use std::path::{Component, Path, PathBuf};

use super::tables::{
    READ_PATH_REDIRECTIONS, STATE_MODIFYING_COMMANDS, WRITE_COMMANDS, WRITE_REDIRECTIONS,
};
use super::tokenize::shell_split;
use super::types::{PermissionMode, ValidationResult};
use super::wrappers::{leads_with_target_hiding_spawner, unwrap_command_wrappers};

/// Relative parent-escape sentinel emitted when a target-hiding spawner
/// (`find -exec` / `xargs`) wraps a write command. `validate_paths` rejects
/// `../` escapes regardless of the policy escape list, so this cannot be
/// allow-listed away — the right posture when the real target is unverifiable.
const UNVERIFIABLE_WRAPPER_TARGET: &str = "../agent-guard-unverifiable-wrapper-write-target";

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
    for target in collect_write_targets(command) {
        let candidate = target.trim_matches(|c| c == '"' || c == '\'');
        if candidate.is_empty() || candidate.starts_with('$') || candidate == "/dev/null" {
            continue;
        }

        let path = Path::new(candidate);
        if path.is_absolute() && !path_stays_within_workspace(path, &workspace) {
            // Absolute path outside the workspace gets one last chance via the
            // policy-declared escape list. Relative `../` escape (below) does
            // not — that vector is always suspicious regardless of policy.
            if matches_escape_glob(candidate, escape_paths) {
                continue;
            }
            return ValidationResult::Block {
                reason: format!(
                    "write target '{}' is outside the configured workspace",
                    candidate
                ),
            };
        }

        if !path.is_absolute() && has_parent_dir_escape(path) {
            return ValidationResult::Block {
                reason: format!(
                    "write target '{}' escapes the configured workspace",
                    candidate
                ),
            };
        }
    }

    for target in collect_read_targets(command) {
        let candidate = target.trim_matches(|c| c == '"' || c == '\'');
        if candidate.is_empty() || candidate.starts_with('$') || candidate == "/dev/null" {
            continue;
        }

        let path = Path::new(candidate);
        if path.is_absolute() && !path_stays_within_workspace(path, &workspace) {
            if matches_escape_glob(candidate, escape_paths) {
                continue;
            }
            return ValidationResult::Block {
                reason: format!(
                    "read target '{}' is outside the configured workspace",
                    candidate
                ),
            };
        }

        if !path.is_absolute() && has_parent_dir_escape(path) {
            return ValidationResult::Block {
                reason: format!(
                    "read target '{}' escapes the configured workspace",
                    candidate
                ),
            };
        }
    }

    ValidationResult::Allow
}

fn matches_escape_glob(candidate: &str, escape_paths: &[String]) -> bool {
    escape_paths.iter().any(|pat| {
        glob::Pattern::new(pat)
            .map(|g| g.matches(candidate))
            .unwrap_or(false)
    })
}

pub fn validate_sed(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode == PermissionMode::ReadOnly
        && (command.contains("-i") || command.contains("--in-place"))
    {
        return ValidationResult::Block {
            reason: "Sed in-place editing is not allowed in read-only mode".to_string(),
        };
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

fn collect_write_targets(command: &str) -> Vec<String> {
    let tokens = shell_split(command);
    let mut targets = Vec::new();
    let mut current_segment = Vec::new();

    for token in tokens {
        if matches!(token.as_str(), "|" | "||" | "&&" | ";" | "&") {
            targets.extend(write_targets_for_segment(&current_segment));
            current_segment.clear();
            continue;
        }
        current_segment.push(token);
    }

    targets.extend(write_targets_for_segment(&current_segment));
    targets
}

fn write_targets_for_segment(segment: &[String]) -> Vec<String> {
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
        if let Some(cmd) = segment.first().map(|s| s.as_str()) {
            if WRITE_COMMANDS.contains(&cmd) || STATE_MODIFYING_COMMANDS.contains(&cmd) {
                return vec![UNVERIFIABLE_WRAPPER_TARGET.to_string()];
            }
        }
    }

    let mut targets = Vec::new();

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
    let Some(command) = positional.first().map(|token| token.as_str()) else {
        return targets;
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
        "mv" | "cp" => {
            // Destination is the last non-flag arg; sources are read-only
            // and not aliased post-op, so they remain out of scope here.
            if let Some(last) = args.iter().rev().find(|token| !token.starts_with('-')) {
                targets.push(last.to_string());
            }
        }
        "ln" | "link" => {
            // Both `ln -s` (symlink) and `ln` / `link` (hardlink) bind the
            // created name to the source: symlinks follow the source for
            // future writes, hardlinks share its inode. Treat every non-flag
            // arg as a target so a workspace-internal link whose source
            // points outside the workspace is rejected (closes the
            // 2026-05-14 HIGH path-traversal-escape finding).
            targets.extend(
                args.iter()
                    .filter(|token| !token.starts_with('-'))
                    .map(|token| token.to_string()),
            );
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
        "tar" => {
            targets.extend(tar_archive_write_target(args));
        }
        _ => {}
    }

    targets
}

/// Extract the archive path that `tar` *writes* to, or an empty vec when the
/// invocation is not an archive-creating/appending one (extract/list read the
/// archive instead, and their output goes to the cwd, which the normal path
/// scan already governs).
///
/// Handles the common forms: short bundles (`-cf`, `-czf`), the old dashless
/// first-arg bundle (`tar czf out.tar .`), and the long options
/// (`--create`, `--file=out.tar`, `--file out.tar`). Exotic invocations
/// (e.g. extraction redirected elsewhere via `-C`) remain best-effort; this
/// closes the `tar -cf /etc/evil.tar .` write-escape from the HIGH-1 finding.
fn tar_archive_write_target(args: &[&String]) -> Vec<String> {
    let mut is_write_mode = false;
    let mut archive: Option<String> = None;
    let mut expect_file = false;

    for (index, token) in args.iter().enumerate() {
        let t = token.as_str();
        if expect_file {
            archive = Some(t.to_string());
            expect_file = false;
            continue;
        }
        if let Some(rest) = t.strip_prefix("--file=") {
            archive = Some(rest.to_string());
            continue;
        }
        match t {
            "--file" => expect_file = true,
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
                }
            }
        }
    }

    match archive {
        Some(path) if is_write_mode && !path.is_empty() && path != "-" => vec![path],
        _ => Vec::new(),
    }
}

fn collect_read_targets(command: &str) -> Vec<String> {
    let tokens = shell_split(command);
    let mut targets = Vec::new();
    let mut current_segment = Vec::new();

    for token in tokens {
        if matches!(token.as_str(), "|" | "||" | "&&" | ";" | "&") {
            targets.extend(read_targets_for_segment(&current_segment));
            current_segment.clear();
            continue;
        }
        current_segment.push(token);
    }

    targets.extend(read_targets_for_segment(&current_segment));
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
