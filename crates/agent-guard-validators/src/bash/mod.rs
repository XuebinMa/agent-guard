//! Bash command validation.
//!
//! The implementation is split across focused submodules; this module owns the
//! top-level `validate_bash_command` orchestration and re-exports the public
//! validation surface so existing `agent_guard_validators::bash::*` callers are
//! unaffected.

use std::path::Path;

mod ast;
mod destructive;
mod git_push;
mod paths;
mod read_only;
mod tables;
mod tokenize;
mod types;
mod wrappers;

#[cfg(test)]
mod tests;

pub use destructive::check_destructive;
pub use git_push::{git_push_intents, GitPushDetection, GitPushIntent};
pub use paths::{validate_paths, validate_sed};
pub use read_only::validate_read_only;
pub use types::{CommandIntent, PermissionMode, ValidationResult};

use ast::{parse_shell, ShellParse};
use tokenize::{
    contains_code_laundering_command, contains_command_substitution, contains_dynamic_command_word,
    contains_env_split_string, contains_interpreter_with_inline_code,
    contains_multiple_find_exec_actions, contains_opaque_interpreter_execution,
    extract_first_command, reparsed_watch_commands,
};
use wrappers::{
    classify_command_launcher, command_name, unwrap_command_wrappers, LauncherDisposition,
};

/// Canonical command spellings for policy matching.
///
/// Each parsed command contributes its normalized direct spelling and, when
/// applicable, a second spelling with transparent launchers removed. Static
/// shell quoting/escaping has already been evaluated by the AST front-end, and
/// the executable is reduced to its basename. Policy evaluation can therefore
/// apply one `prefix: "sudo "` or `prefix: "git push"` rule to `"sudo"`,
/// `/usr/bin/git`, and `stdbuf -o0 git` without weakening a decision made from
/// the original payload.
pub fn canonical_policy_subjects(command: &str) -> Result<Vec<String>, String> {
    let commands = match parse_shell(command) {
        ShellParse::Understood(commands) => commands,
        ShellParse::TooComplex(reason) => return Err(reason),
    };
    let mut subjects = Vec::new();

    for resolved in commands {
        if let Some(direct) = canonical_argv(&resolved.argv) {
            if !subjects.contains(&direct) {
                subjects.push(direct);
            }
        }

        let unwrapped = unwrap_command_wrappers(&resolved.argv);
        if unwrapped.len() != resolved.argv.len() {
            if let Some(unwrapped) = canonical_argv(unwrapped) {
                if !subjects.contains(&unwrapped) {
                    subjects.push(unwrapped);
                }
            }
        }
    }

    Ok(subjects)
}

fn canonical_argv<S: AsRef<str>>(argv: &[S]) -> Option<String> {
    let (first, rest) = argv.split_first()?;
    let mut subject = command_name(first.as_ref()).to_string();
    for argument in rest {
        subject.push(' ');
        subject.push_str(argument.as_ref());
    }
    Some(subject)
}

pub fn validate_bash_command(
    command: &str,
    mode: PermissionMode,
    workspace_path: &Path,
    escape_paths: &[String],
) -> ValidationResult {
    if mode == PermissionMode::Blocked {
        return ValidationResult::Block {
            reason: "tool is in blocked mode".to_string(),
        };
    }

    // Gate substitution before policy checks: if a substituted command or
    // path target is opaque to the validator, no downstream policy decision
    // can be trusted. Matches the scope of `validate_paths` (ReadOnly +
    // WorkspaceWrite); DangerFullAccess accepts opaque payloads by design.
    if matches!(
        mode,
        PermissionMode::ReadOnly | PermissionMode::WorkspaceWrite
    ) {
        // Syntax the grammar cannot parse, or a construct the walker does not
        // model, cannot be classified by any gate below — so no downstream
        // decision would be truthful. Reject before anything else runs.
        match parse_shell(command) {
            ShellParse::TooComplex(reason) => {
                return ValidationResult::Block {
                    reason: format!("Command cannot be validated in this mode: {reason}"),
                };
            }
            ShellParse::Understood(commands) => {
                for resolved in commands {
                    match classify_command_launcher(&resolved.argv) {
                        LauncherDisposition::Opaque(launcher) => {
                            return ValidationResult::Block {
                                reason: format!(
                                    "Command launcher '{launcher}' can spawn an uninspected child and is not supported in this mode"
                                ),
                            };
                        }
                        LauncherDisposition::ExistingProcess(launcher) => {
                            return ValidationResult::Block {
                                reason: format!(
                                    "Command launcher '{launcher}' operates on an existing process and is not supported in this mode"
                                ),
                            };
                        }
                        LauncherDisposition::Transparent | LauncherDisposition::Ordinary => {}
                    }
                }
            }
        }
        if let Some(pat) = contains_command_substitution(command) {
            return ValidationResult::Block {
                reason: format!(
                    "Command contains shell substitution '{pat}' whose inner command cannot be validated"
                ),
            };
        }
        if let Some(builtin) = contains_code_laundering_command(command) {
            return ValidationResult::Block {
                reason: format!(
                    "Builtin '{builtin}' re-parses its arguments as shell code and is not allowed"
                ),
            };
        }
        if let Some((interp, flag)) = contains_interpreter_with_inline_code(command) {
            return ValidationResult::Block {
                reason: format!(
                    "Interpreter '{interp}' invoked with inline-code flag '{flag}' is not allowed in this mode"
                ),
            };
        }
        if let Some(interpreter) = contains_opaque_interpreter_execution(command) {
            return ValidationResult::Block {
                reason: format!(
                    "Interpreter '{interpreter}' would execute code the validator cannot inspect in this mode"
                ),
            };
        }
        if contains_dynamic_command_word(command) {
            return ValidationResult::Block {
                reason:
                    "A shell parameter expansion cannot be used as the command word in this mode"
                        .to_string(),
            };
        }
        // Parenthesized grouping used to be rejected outright, because the flat
        // segment validator could not see inside it. The grammar models it as a
        // `subshell` node, so the commands within are classified like any
        // others and the blanket rejection is no longer needed.
        if contains_multiple_find_exec_actions(command) {
            return ValidationResult::Block {
                reason: "Multiple find -exec/-execdir actions are not supported in this mode"
                    .to_string(),
            };
        }
        if contains_env_split_string(command) {
            return ValidationResult::Block {
                reason: "env -S/--split-string can inject an opaque command and is not supported in this mode"
                    .to_string(),
            };
        }
        for inner in reparsed_watch_commands(command) {
            let result = validate_bash_command(&inner, mode, workspace_path, escape_paths);
            if result != ValidationResult::Allow {
                return result;
            }
        }
    }

    let res = validate_read_only(command, mode);
    if res != ValidationResult::Allow {
        return res;
    }

    let res = validate_paths(command, mode, workspace_path, escape_paths);
    if res != ValidationResult::Allow {
        return res;
    }

    check_destructive(command)
}

pub fn classify_intent(command: &str) -> CommandIntent {
    let first = extract_first_command(command);
    match command_name(&first) {
        "ls" | "cat" | "pwd" | "git" => {
            if command.contains("push")
                || command.contains("commit")
                || command.contains("checkout")
            {
                CommandIntent::Write
            } else {
                CommandIntent::ReadOnly
            }
        }
        "rm" | "mkfs" | "dd" => CommandIntent::Destructive,
        "cp" | "mv" | "touch" | "sed" => CommandIntent::Write,
        "curl" | "wget" | "ping" => CommandIntent::Network,
        "npm" | "pip" | "apt" | "apt-get" | "yum" => CommandIntent::PackageManagement,
        "sudo" | "su" | "systemctl" => CommandIntent::SystemAdmin,
        _ => CommandIntent::Unknown,
    }
}

pub fn validate_command(
    command: &str,
    mode: PermissionMode,
    _workspace: &Path,
    escape_paths: &[String],
) -> ValidationResult {
    validate_bash_command(command, mode, _workspace, escape_paths)
}

pub fn validate_mode(command: &str, mode: PermissionMode) -> ValidationResult {
    validate_read_only(command, mode)
}
