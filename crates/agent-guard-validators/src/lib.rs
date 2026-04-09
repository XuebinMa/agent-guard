pub mod bash;
pub mod path;

#[cfg(test)]
mod tests;

pub use bash::{
    check_destructive, classify_intent, validate_bash_command, validate_command, validate_mode,
    validate_paths, validate_read_only, validate_sed, CommandIntent, PermissionMode, ValidationResult
};
