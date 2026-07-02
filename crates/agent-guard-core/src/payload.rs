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

/// Upper bound on a tool payload we are willing to parse (CWE-770: prevent
/// memory exhaustion). Shared by field extraction and the read-only intrinsic
/// classification so both apply the same cap.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Extracted, structured payload values used by the policy engine.
#[derive(Debug, Clone)]
pub enum ExtractedPayload<'a> {
    /// Raw string — used for Custom tools; rules match against this directly.
    Raw(&'a str),
    /// File path extracted from `{"path": "..."}`.
    Path(String),
    /// URL + normalized HTTP method extracted from
    /// `{"url": "...", "method": "..."}` (used by Tool::HttpRequest).
    Http { url: String, method: String },
    /// Command extracted from `{"command": "..."}` (used by Tool::Bash).
    Command(String),
}

impl<'a> ExtractedPayload<'a> {
    /// The string value that policy rules should match against.
    pub fn match_value(&self) -> &str {
        match self {
            Self::Raw(s) => s,
            Self::Path(s) | Self::Command(s) => s.as_str(),
            Self::Http { url, .. } => url.as_str(),
        }
    }

    /// The normalized (uppercase) HTTP method for an `HttpRequest` payload, or
    /// `None` for any other tool. Consumed by method-aware policy matching.
    pub fn http_method(&self) -> Option<&str> {
        match self {
            Self::Http { method, .. } => Some(method.as_str()),
            _ => None,
        }
    }
}

/// Extract path from `{"path": "..."}` (used by ReadFile / WriteFile).
pub fn extract_path(payload: &str) -> Result<ExtractedPayload<'_>, GuardDecision> {
    extract_string_field(payload, "path").map(ExtractedPayload::Path)
}

/// Extract url + normalized method from `{"url": "...", "method": "..."}`
/// (used by HttpRequest). `url` is required; `method` defaults to `GET` and is
/// uppercased so policy rules can match on it case-insensitively.
pub fn extract_http_request(payload: &str) -> Result<ExtractedPayload<'_>, GuardDecision> {
    // CWE-770: bound payload size, mirroring extract_string_field.
    if payload.len() > 1024 * 1024 {
        return Err(GuardDecision::deny(
            DecisionCode::InvalidPayload,
            "payload exceeds maximum size of 1MB".to_string(),
        ));
    }
    let v: serde_json::Value = serde_json::from_str(payload).map_err(|_| {
        GuardDecision::deny(
            DecisionCode::InvalidPayload,
            "payload is not valid JSON (expected {\"url\":\"...\"})".to_string(),
        )
    })?;
    let url = match v.get("url").and_then(|u| u.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return Err(GuardDecision::deny(
                DecisionCode::MissingPayloadField,
                "payload is missing required field 'url' (expected {\"url\":\"...\"})".to_string(),
            ))
        }
    };
    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_else(|| "GET".to_string());
    Ok(ExtractedPayload::Http { url, method })
}

/// Extract command from `{"command": "..."}` (used by Tool::Bash).
pub fn extract_bash_command(payload: &str) -> Result<ExtractedPayload<'_>, GuardDecision> {
    extract_string_field(payload, "command").map(ExtractedPayload::Command)
}

fn extract_string_field(payload: &str, field: &str) -> Result<String, GuardDecision> {
    // CWE-770: Limit payload size to 1MB to prevent memory exhaustion
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(GuardDecision::deny(
            DecisionCode::InvalidPayload,
            "payload exceeds maximum size of 1MB".to_string(),
        ));
    }
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
