pub mod bash;
pub mod path;

pub use bash::{
    check_destructive, classify_intent, validate_bash_command, validate_command, validate_mode,
    validate_paths, validate_read_only, validate_sed, CommandIntent, PermissionMode,
    ValidationResult,
};
pub use path::{
    detect_trust_prompt, path_matches_trusted_root, validate_path_access, TrustConfig,
    TrustDecision, TrustEvent, TrustPolicy, TrustResolver,
};
