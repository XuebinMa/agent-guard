//! Read-only mode validation: rejects filesystem/state-mutating commands.

use super::tables::{
    DANGEROUS_ENV_VAR_PREFIXES, STATE_MODIFYING_COMMANDS, WRITE_COMMANDS, WRITE_REDIRECTIONS,
};
use super::tokenize::shell_split;
use super::types::{PermissionMode, ValidationResult};
use super::wrappers::unwrap_command_wrappers;

#[must_use]
pub fn validate_read_only(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        return ValidationResult::Allow;
    }

    // Industrial Standard Mitigation: Proper shell splitting that respects quotes
    let parts = shell_split(command);

    // Token-prefix scan for dangerous env-var assignments. Runs over the
    // post-quote-strip tokens, so quoting tricks (`L'D'_PRELOAD=...`) are
    // caught and benign filename matches are not.
    for token in &parts {
        for &prefix in DANGEROUS_ENV_VAR_PREFIXES {
            if token.starts_with(prefix) {
                return ValidationResult::Block {
                    reason: format!(
                        "Environment variable injection attempt detected ({}…)",
                        prefix.trim_end_matches('=')
                    ),
                };
            }
        }
    }

    let mut current_cmd_parts = Vec::new();
    for part in parts {
        if part == "|" || part == ";" || part == "&&" || part == "||" || part == "&" {
            if let Some(res) = check_command_segment(&current_cmd_parts) {
                return res;
            }
            current_cmd_parts.clear();
        } else {
            current_cmd_parts.push(part);
        }
    }

    if let Some(res) = check_command_segment(&current_cmd_parts) {
        return res;
    }

    for &redir in WRITE_REDIRECTIONS {
        if command.contains(redir) {
            return ValidationResult::Block {
                reason: format!(
                    "Command contains write redirection '{redir}' which is not allowed in read-only mode"
                ),
            };
        }
    }

    ValidationResult::Allow
}

fn check_command_segment(parts: &[String]) -> Option<ValidationResult> {
    if parts.is_empty() {
        return None;
    }

    // Detect process substitution (CWE-78) over the full, un-unwrapped segment.
    for part in parts {
        if part.contains("<(") || part.contains(">(") {
            return Some(ValidationResult::Block {
                reason: "Shell process substitution is not allowed in read-only mode".to_string(),
            });
        }
    }

    // Strip transparent wrappers (`sudo`/`env`/`nice`/`nohup`/`timeout`/`doas`)
    // and `NAME=value` prefixes so the *real* command word — not a wrapper flag
    // or operand — drives the checks below. Without this, `sudo -u root rm`,
    // `env FOO=1 rm`, or `FOO=1 rm` hid the destructive command from this gate
    // (audit 2026-05-18 / 2026-05-19 / 2026-06-08).
    let parts = unwrap_command_wrappers(parts);
    let first_command = parts.first()?;

    if first_command == "git" {
        if parts.len() > 1 {
            let sub = &parts[1];
            let write_subs = [
                "commit", "push", "pull", "merge", "checkout", "add", "rebase", "reset", "init",
            ];
            if write_subs.contains(&sub.as_str()) {
                return Some(ValidationResult::Block {
                    reason: format!("Git command '{sub}' modifies the repository and is not allowed in read-only mode"),
                });
            }
        }
        return None;
    }

    if first_command == "sed" {
        if parts
            .iter()
            .any(|p| p == "-i" || p.starts_with("--in-place"))
        {
            return Some(ValidationResult::Block {
                reason: "Sed in-place editing is not allowed in read-only mode".to_string(),
            });
        }
        return None;
    }

    for &write_cmd in WRITE_COMMANDS {
        if first_command == write_cmd {
            return Some(ValidationResult::Block {
                reason: format!(
                    "Command '{write_cmd}' modifies the filesystem and is not allowed in read-only mode"
                ),
            });
        }
    }

    for &state_cmd in STATE_MODIFYING_COMMANDS {
        if first_command == state_cmd {
            return Some(ValidationResult::Block {
                reason: format!(
                    "Command '{state_cmd}' modifies system state and is not allowed in read-only mode"
                ),
            });
        }
    }

    // Wrapper layers (`sudo`/`env`/…) are stripped up front by
    // `unwrap_command_wrappers`, so `first_command` is already the real command.

    // Interpreter-laundering check lives in `validate_bash_command`'s
    // early gate (see `contains_interpreter_with_inline_code`); it now
    // covers both ReadOnly and WorkspaceWrite modes, so no per-segment
    // check is needed here.

    None
}
