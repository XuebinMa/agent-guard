//! S6-4b: content-layer enforcement stage.
//!
//! Scans the outbound payload of a tool call for secrets / PII and, under
//! [`ContentMode::Block`], converts findings into a deny decision. This is the
//! *decision-only* path: it runs inside `Guard::check` / `evaluate` and can
//! therefore only **allow** or **deny** — it cannot rewrite the payload.
//!
//! - `Block` + findings  → `Deny { SensitiveContentBlocked }`
//! - `Warn` / `Mask`     → `None` (allow in the check path)
//!
//! Mask rewriting and Warn finding-audit emission require a payload-rewriting
//! execution path and land in S6-4c (`Guard::run`). Keeping them out of the
//! decision path avoids pretending `check` masked anything it did not.
//!
//! The deny message lists only finding-kind labels (e.g. "AWS Access Key"),
//! never the matched substring, so audit records never carry raw secrets.

use agent_guard_core::{
    ContentDetector, ContentMode, ContentPolicy, DecisionCode, GuardDecision, Tool,
};
use agent_guard_validators::content::{scan_pii, scan_secrets};

/// Apply a tool's content policy to its payload.
///
/// Returns `Some(Deny)` when Block mode finds sensitive content, otherwise
/// `None` (meaning "no content-layer objection" — the caller keeps its
/// existing decision).
pub(crate) fn apply_content_policy(
    policy: &ContentPolicy,
    tool: &Tool,
    payload: &str,
) -> Option<GuardDecision> {
    // Only Block mode changes a decision in the check path. Warn/Mask are
    // realised in the execution path (S6-4c).
    if policy.mode != ContentMode::Block {
        return None;
    }

    let text = scannable_text(tool, payload)?;
    let labels = finding_labels(&policy.detect, &text);
    if labels.is_empty() {
        return None;
    }

    Some(GuardDecision::deny(
        DecisionCode::SensitiveContentBlocked,
        format!(
            "blocked: {} sensitive item(s) detected in outbound content ({})",
            labels.len(),
            labels.join(", ")
        ),
    ))
}

/// Extract the scannable text for a tool's payload.
///
/// Scope (locked in the S6-4 design): `WriteFile` content + `HttpRequest`
/// body. Other tools have no outbound content surface and are skipped.
fn scannable_text(tool: &Tool, payload: &str) -> Option<String> {
    let field = match tool {
        Tool::WriteFile => "content",
        Tool::HttpRequest => "body",
        _ => return None,
    };
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Collect finding-kind labels (no raw content) for the configured detectors.
fn finding_labels(detectors: &[ContentDetector], text: &str) -> Vec<&'static str> {
    let mut labels = Vec::new();
    for detector in detectors {
        match detector {
            ContentDetector::Secrets => {
                labels.extend(scan_secrets(text).iter().map(|f| f.kind.label()));
            }
            ContentDetector::Pii => {
                labels.extend(scan_pii(text).iter().map(|f| f.kind.label()));
            }
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_guard_core::policy::{ContentDetector, ContentMode, ContentPolicy};

    fn policy(mode: ContentMode, detect: Vec<ContentDetector>) -> ContentPolicy {
        ContentPolicy { mode, detect }
    }

    #[test]
    fn block_mode_denies_when_secret_found_in_write_content() {
        let pol = policy(ContentMode::Block, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"key=AKIAIOSFODNN7EXAMPLE done"}"#;

        let decision = apply_content_policy(&pol, &Tool::WriteFile, payload);

        assert!(matches!(decision, Some(GuardDecision::Deny { .. })));
    }

    #[test]
    fn block_mode_denies_when_pii_found_in_http_body() {
        let pol = policy(ContentMode::Block, vec![ContentDetector::Pii]);
        let payload = r#"{"url":"https://x.test","method":"POST","body":"email a@b.com"}"#;

        let decision = apply_content_policy(&pol, &Tool::HttpRequest, payload);

        assert!(matches!(decision, Some(GuardDecision::Deny { .. })));
    }

    #[test]
    fn deny_message_lists_labels_not_raw_secret() {
        let pol = policy(ContentMode::Block, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"AKIAIOSFODNN7EXAMPLE"}"#;

        let decision = apply_content_policy(&pol, &Tool::WriteFile, payload);

        match decision {
            Some(GuardDecision::Deny { reason }) => {
                assert!(reason.message.contains("AWS Access Key"));
                assert!(!reason.message.contains("AKIAIOSFODNN7EXAMPLE"));
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn clean_content_yields_no_objection() {
        let pol = policy(
            ContentMode::Block,
            vec![ContentDetector::Secrets, ContentDetector::Pii],
        );
        let payload = r#"{"path":"out.txt","content":"just some ordinary prose"}"#;

        assert!(apply_content_policy(&pol, &Tool::WriteFile, payload).is_none());
    }

    #[test]
    fn warn_mode_never_objects_in_check_path() {
        let pol = policy(ContentMode::Warn, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"AKIAIOSFODNN7EXAMPLE"}"#;

        assert!(apply_content_policy(&pol, &Tool::WriteFile, payload).is_none());
    }

    #[test]
    fn mask_mode_never_objects_in_check_path() {
        let pol = policy(ContentMode::Mask, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"AKIAIOSFODNN7EXAMPLE"}"#;

        assert!(apply_content_policy(&pol, &Tool::WriteFile, payload).is_none());
    }

    #[test]
    fn detector_not_configured_is_not_scanned() {
        // Only PII configured; a secret in content must not trip the deny.
        let pol = policy(ContentMode::Block, vec![ContentDetector::Pii]);
        let payload = r#"{"path":"out.txt","content":"AKIAIOSFODNN7EXAMPLE"}"#;

        assert!(apply_content_policy(&pol, &Tool::WriteFile, payload).is_none());
    }

    #[test]
    fn unscoped_tool_yields_no_objection() {
        let pol = policy(ContentMode::Block, vec![ContentDetector::Secrets]);
        let payload = r#"{"command":"echo AKIAIOSFODNN7EXAMPLE"}"#;

        assert!(apply_content_policy(&pol, &Tool::Bash, payload).is_none());
    }
}
