//! Destructive-command warnings for recursive deletes, shred, and similar.

use super::tables::{ALWAYS_DESTRUCTIVE_COMMANDS, DESTRUCTIVE_PATTERNS};
use super::tokenize::extract_first_command;
use super::types::ValidationResult;

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

    let first = extract_first_command(command);
    if ALWAYS_DESTRUCTIVE_COMMANDS.contains(&&*first) {
        return ValidationResult::Warn {
            message: format!("Command '{first}' is inherently destructive and dangerous"),
        };
    }

    ValidationResult::Allow
}
