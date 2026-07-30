//! Bash command validation.
//!
//! The implementation is split across focused submodules; this module owns the
//! top-level `validate_bash_command` orchestration and re-exports the public
//! validation surface so existing `agent_guard_validators::bash::*` callers are
//! unaffected.

use std::path::Path;

mod destructive;
mod paths;
mod read_only;
mod tables;
mod tokenize;
mod types;
mod wrappers;

#[cfg(test)]
mod tests;

pub use destructive::check_destructive;
pub use paths::{validate_paths, validate_sed};
pub use read_only::validate_read_only;
pub use types::{CommandIntent, PermissionMode, ValidationResult};

use tokenize::{
    contains_code_laundering_command, contains_command_substitution, contains_dynamic_command_word,
    contains_env_split_string, contains_interpreter_with_inline_code,
    contains_multiple_find_exec_actions, contains_opaque_interpreter_execution,
    contains_shell_grouping, extract_first_command, reparsed_watch_commands,
};
use wrappers::command_name;

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
        if contains_shell_grouping(command) {
            return ValidationResult::Block {
                reason: "Parenthesized shell grouping is not supported in this mode".to_string(),
            };
        }
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
