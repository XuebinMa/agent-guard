//! Tool-aware payload extractor.
//!
//! `GuardInput.payload` is defined as the raw JSON string forwarded from an agent
//! framework.  Before policy rules can meaningfully match path/URL values, we must
//! extract the relevant field from that JSON rather than matching the raw string.
//!
//! Extraction contract:
//! - payload is valid JSON **and** contains the expected field → return the field value.
//! - payload is valid JSON **but** is missing the required field → Err(MissingPayloadField).
//! - payload is **not** valid JSON → Err(InvalidPayload).
//! - Tool::Bash and Tool::Custom(…) → no extraction needed; rules apply to the raw payload.

use crate::decision::{DecisionCode, GuardDecision};

/// Extracted, structured payload values used by the policy engine.
#[derive(Debug, Clone)]
pub enum ExtractedPayload<'a> {
    /// Raw string — used for Custom tools; rules match against this directly.
    Raw(&'a str),
    /// File path extracted from `{"path": "..."}`.
    Path(String),
    /// URL extracted from `{"url": "..."}`.
    Url(String),
    /// Command extracted from `{"command": "..."}` (used by Tool::Bash).
    Command(String),
}

impl<'a> ExtractedPayload<'a> {
    /// The string value that policy rules should match against.
    pub fn match_value(&self) -> &str {
        match self {
            Self::Raw(s) => s,
            Self::Path(s) | Self::Url(s) | Self::Command(s) => s.as_str(),
        }
    }
}

/// Extract path from `{"path": "..."}` (used by ReadFile / WriteFile).
pub fn extract_path(payload: &str) -> Result<ExtractedPayload<'_>, GuardDecision> {
    extract_string_field(payload, "path")
        .map(ExtractedPayload::Path)
}

/// Extract url from `{"url": "..."}` (used by HttpRequest).
pub fn extract_url(payload: &str) -> Result<ExtractedPayload<'_>, GuardDecision> {
    extract_string_field(payload, "url")
        .map(ExtractedPayload::Url)
}

/// Extract command from `{"command": "..."}` (used by Tool::Bash).
pub fn extract_bash_command(payload: &str) -> Result<ExtractedPayload<'_>, GuardDecision> {
    extract_string_field(payload, "command")
        .map(ExtractedPayload::Command)
}

fn extract_string_field(payload: &str, field: &str) -> Result<String, GuardDecision> {
    let v: serde_json::Value = serde_json::from_str(payload).map_err(|_| {
        GuardDecision::deny(
            DecisionCode::InvalidPayload,
            format!(
                "payload is not valid JSON (expected {{\"{}\":\"...\"}})",
                field
            ),
        )
    })?;

    match v.get(field).and_then(|f| f.as_str()) {
        Some(s) => Ok(s.to_string()),
        None => Err(GuardDecision::deny(
            DecisionCode::MissingPayloadField,
            format!(
                "payload is missing required field '{}' (expected {{\"{}\":\"...\"}})",
                field, field
            ),
        )),
    }
}
