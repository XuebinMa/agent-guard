//! Destructive-command warnings for recursive deletes, shred, and similar.

use super::ast::{parse_shell, ShellParse};
use super::tables::{ALWAYS_DESTRUCTIVE_COMMANDS, DESTRUCTIVE_PATTERNS};
use super::tokenize::extract_first_command;
use super::types::ValidationResult;
use super::wrappers::{command_name, unwrap_command_wrappers};

#[must_use]
pub fn check_destructive(command: &str) -> ValidationResult {
    let normalized = command.to_lowercase();
    for (pattern, message) in DESTRUCTIVE_PATTERNS {
        if normalized.contains(pattern) {
            return ValidationResult::Warn {
                message: message.to_string(),
            };
        }
    }

    // Every command position, not just the first word of the line: a
    // destructive command nested in a grouping construct — or sequenced after
    // a benign one — is still a destructive command.
    for first in destructive_candidates(command) {
        if ALWAYS_DESTRUCTIVE_COMMANDS.contains(&first.as_str()) {
            return ValidationResult::Warn {
                message: format!("Command '{first}' is inherently destructive and dangerous"),
            };
        }
    }

    ValidationResult::Allow
}

/// The command word of each command position, with transparent wrappers
/// stripped so `sudo shred …` is classified as `shred`.
///
/// Falls back to the leading word when the input does not parse, which keeps
/// this function honest on its own; `validate_bash_command` rejects
/// unparseable input in restricted modes before reaching here.
fn destructive_candidates(command: &str) -> Vec<String> {
    match parse_shell(command) {
        ShellParse::Understood(commands) => commands
            .iter()
            .filter_map(|resolved| {
                unwrap_command_wrappers(&resolved.argv)
                    .first()
                    .map(|word| command_name(word).to_string())
            })
            .collect(),
        ShellParse::TooComplex(_) => {
            vec![command_name(&extract_first_command(command)).to_string()]
        }
    }
}
