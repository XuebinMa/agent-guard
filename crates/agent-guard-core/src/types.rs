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
    pub fn name(&self) -> &str {
        match self {
            Tool::Bash => "bash",
            Tool::ReadFile => "read_file",
            Tool::WriteFile => "write_file",
            Tool::HttpRequest => "http_request",
            Tool::Custom(id) => id.as_str(),
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
    const BUILTIN_NAMES: &'static [&'static str] =
        &["bash", "read_file", "write_file", "http_request"];

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
        if Self::BUILTIN_NAMES.contains(&id.to_lowercase().as_str()) {
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    #[default]
    Untrusted,
    Trusted,
    Admin,
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
