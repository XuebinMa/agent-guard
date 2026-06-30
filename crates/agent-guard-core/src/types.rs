use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Tool ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tool {
    Bash,
    ReadFile,
    WriteFile,
    HttpRequest,
    Custom(CustomToolId),
}

impl Tool {
    /// Canonical names of the built-in (non-`Custom`) variants, exactly as
    /// produced by `name()` and accepted by `from_builtin_name()`. This is
    /// the single source of truth the bindings parse against; their parity
    /// tests iterate this list.
    pub const BUILTIN_NAMES: &'static [&'static str] =
        &["bash", "read_file", "write_file", "http_request"];

    pub fn name(&self) -> &str {
        match self {
            Tool::Bash => "bash",
            Tool::ReadFile => "read_file",
            Tool::WriteFile => "write_file",
            Tool::HttpRequest => "http_request",
            Tool::Custom(id) => id.as_str(),
        }
    }

    /// Parse a canonical built-in tool name. Returns `None` for anything
    /// else; callers route those through `CustomToolId::new` to build
    /// `Tool::Custom`.
    pub fn from_builtin_name(name: &str) -> Option<Tool> {
        match name {
            "bash" => Some(Tool::Bash),
            "read_file" => Some(Tool::ReadFile),
            "write_file" => Some(Tool::WriteFile),
            "http_request" => Some(Tool::HttpRequest),
            _ => None,
        }
    }
}

impl std::fmt::Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── CustomToolId ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CustomToolId(String);

impl CustomToolId {
    const MAX_LEN: usize = 64;

    pub fn new(id: impl Into<String>) -> Result<Self, CustomToolIdError> {
        let id = id.into();
        if id.is_empty() || id.len() > Self::MAX_LEN {
            return Err(CustomToolIdError::InvalidLength);
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            return Err(CustomToolIdError::InvalidChars);
        }
        if Tool::BUILTIN_NAMES.contains(&id.to_lowercase().as_str()) {
            return Err(CustomToolIdError::ConflictsWithBuiltin(id));
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum CustomToolIdError {
    #[error("id must be 1-64 characters")]
    InvalidLength,
    #[error("id may only contain [a-zA-Z0-9._-]")]
    InvalidChars,
    #[error("'{0}' conflicts with a builtin tool name")]
    ConflictsWithBuiltin(String),
}

// ── TrustLevel ────────────────────────────────────────────────────────────────
//
// SECURITY INVARIANT: The default value is `Untrusted`.
// Any context without an explicit trust_level MUST be treated as Untrusted.
// Bindings and integrations MUST NOT assume a higher trust level.

// Variants are ordered by increasing privilege so the derived `Ord` supports
// threshold checks (`trust >= TrustLevel::Trusted`).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    #[default]
    Untrusted,
    Trusted,
    Admin,
}

impl TrustLevel {
    /// Every variant, in declaration order. Bindings parse against `name()`
    /// / `from_name()`; their parity tests iterate this list.
    pub const ALL: [TrustLevel; 3] = [
        TrustLevel::Untrusted,
        TrustLevel::Trusted,
        TrustLevel::Admin,
    ];

    /// Canonical snake_case name, matching the serde encoding.
    pub fn name(&self) -> &'static str {
        match self {
            TrustLevel::Untrusted => "untrusted",
            TrustLevel::Trusted => "trusted",
            TrustLevel::Admin => "admin",
        }
    }

    /// Parse a canonical trust-level name. Returns `None` for unknown names
    /// so callers fail closed rather than guessing.
    pub fn from_name(name: &str) -> Option<TrustLevel> {
        match name {
            "untrusted" => Some(TrustLevel::Untrusted),
            "trusted" => Some(TrustLevel::Trusted),
            "admin" => Some(TrustLevel::Admin),
            _ => None,
        }
    }
}

// ── Context ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
    /// The human or service account initiating the action.
    pub actor: Option<String>,
    /// Defaults to Untrusted — see TrustLevel invariant above.
    pub trust_level: TrustLevel,
    pub working_directory: Option<PathBuf>,
}

// ── GuardInput ────────────────────────────────────────────────────────────────
//
// Phase 1: `payload` is a raw JSON string passed directly from the agent framework.
// Future: typed `parsed_payload` helpers will be added for Python/Node bindings
// to avoid forcing callers to serialize/deserialize manually.

#[derive(Debug, Clone)]
pub struct GuardInput {
    pub tool: Tool,
    pub payload: String,
    /// Security context for this request. Defaults to Untrusted if not set.
    pub context: Context,
}

impl GuardInput {
    pub fn new(tool: Tool, payload: impl Into<String>) -> Self {
        Self {
            tool,
            payload: payload.into(),
            context: Context::default(), // Untrusted by default
        }
    }

    pub fn with_context(mut self, ctx: Context) -> Self {
        self.context = ctx;
        self
    }
}
