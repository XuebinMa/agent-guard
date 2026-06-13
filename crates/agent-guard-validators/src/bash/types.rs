//! Permission mode, validation result, and command-intent types.

/// Effective permission mode for a bash command, mirroring the policy
/// engine's `PolicyMode`. These are *modes*, not verdicts: the validator
/// maps each to an `Allow`/`Block`/`Warn` `ValidationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    Blocked,
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Allow,
    Block { reason: String },
    Warn { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandIntent {
    ReadOnly,
    Write,
    Execute,
    Network,
    PackageManagement,
    SystemAdmin,
    Destructive,
    Unknown,
}
