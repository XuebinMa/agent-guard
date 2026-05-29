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
use agent_guard_validators::content::{
    redact_content, scan_pii, scan_secrets, RedactionMode, SensitiveSpan,
};

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

/// Outcome of applying a content policy on the execution path.
///
/// Produced only for `Mask` / `Warn` modes with at least one finding. `Block`
/// is handled earlier in the decision path and never reaches here.
pub(crate) struct ContentApplication {
    /// The mode that produced this application (`Mask` or `Warn`).
    pub mode: ContentMode,
    /// Finding-kind labels (no raw content) for auditing.
    pub labels: Vec<String>,
    /// The masked payload to execute instead of the original. `Some` only for
    /// `Mask` mode; `None` for `Warn` (the original payload is executed).
    pub masked_payload: Option<String>,
}

/// Apply a tool's content policy on the execution path (S6-4c).
///
/// - `Block` → `None` (already denied in the decision path).
/// - `Warn`  → `Some` with `masked_payload: None` (execute as-is, audit only).
/// - `Mask`  → `Some` with the payload's scannable field rewritten so each
///   finding becomes a `[REDACTED:<label>]` placeholder.
///
/// Returns `None` when the tool is out of scope or no findings are present.
pub(crate) fn apply_content_for_execution(
    policy: &ContentPolicy,
    tool: &Tool,
    payload: &str,
) -> Option<ContentApplication> {
    if policy.mode == ContentMode::Block {
        return None;
    }

    let text = scannable_text(tool, payload)?;
    let spans = finding_spans(&policy.detect, &text);
    if spans.is_empty() {
        return None;
    }

    let labels: Vec<String> = spans.iter().map(|s| s.label.to_string()).collect();

    let masked_payload = match policy.mode {
        ContentMode::Mask => {
            let outcome = redact_content(&text, &spans, RedactionMode::Mask);
            rewrite_field(tool, payload, &outcome.content)
        }
        // Warn executes the original payload unchanged.
        _ => None,
    };

    Some(ContentApplication {
        mode: policy.mode,
        labels,
        masked_payload,
    })
}

/// Collect sensitive spans for the configured detectors, ordered by position.
fn finding_spans(detectors: &[ContentDetector], text: &str) -> Vec<SensitiveSpan> {
    let mut spans = Vec::new();
    for detector in detectors {
        match detector {
            ContentDetector::Secrets => {
                spans.extend(scan_secrets(text).iter().map(SensitiveSpan::from_secret));
            }
            ContentDetector::Pii => {
                spans.extend(scan_pii(text).iter().map(SensitiveSpan::from_pii));
            }
        }
    }
    spans.sort_by_key(|s| s.start);
    spans
}

/// Rewrite the tool payload's scannable field with masked text.
///
/// Returns `None` (caller falls back to the original payload) if the payload
/// is not a JSON object — no panic path.
fn rewrite_field(tool: &Tool, payload: &str, masked: &str) -> Option<String> {
    let field = match tool {
        Tool::WriteFile => "content",
        Tool::HttpRequest => "body",
        _ => return None,
    };
    let mut value: serde_json::Value = serde_json::from_str(payload).ok()?;
    let obj = value.as_object_mut()?;
    obj.insert(
        field.to_string(),
        serde_json::Value::String(masked.to_string()),
    );
    serde_json::to_string(&value).ok()
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

    // ── execution path (S6-4c) ────────────────────────────────────────────

    #[test]
    fn mask_rewrites_payload_field_and_reports_labels() {
        let pol = policy(ContentMode::Mask, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"key AKIAIOSFODNN7EXAMPLE end"}"#;

        let app = apply_content_for_execution(&pol, &Tool::WriteFile, payload)
            .expect("mask produces an application");

        assert_eq!(app.mode, ContentMode::Mask);
        assert_eq!(app.labels, vec!["AWS Access Key".to_string()]);
        let masked = app.masked_payload.expect("mask rewrites the payload");
        assert!(masked.contains("[REDACTED:AWS Access Key]"));
        assert!(!masked.contains("AKIAIOSFODNN7EXAMPLE"));
        // Still valid JSON with the other field intact.
        let v: serde_json::Value = serde_json::from_str(&masked).unwrap();
        assert_eq!(v["path"], "out.txt");
    }

    #[test]
    fn warn_reports_labels_without_rewriting() {
        let pol = policy(ContentMode::Warn, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"AKIAIOSFODNN7EXAMPLE"}"#;

        let app = apply_content_for_execution(&pol, &Tool::WriteFile, payload)
            .expect("warn produces an application");

        assert_eq!(app.mode, ContentMode::Warn);
        assert_eq!(app.labels, vec!["AWS Access Key".to_string()]);
        assert!(app.masked_payload.is_none());
    }

    #[test]
    fn block_mode_has_no_execution_application() {
        let pol = policy(ContentMode::Block, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"AKIAIOSFODNN7EXAMPLE"}"#;

        assert!(apply_content_for_execution(&pol, &Tool::WriteFile, payload).is_none());
    }

    #[test]
    fn clean_content_has_no_execution_application() {
        let pol = policy(ContentMode::Mask, vec![ContentDetector::Secrets]);
        let payload = r#"{"path":"out.txt","content":"ordinary prose"}"#;

        assert!(apply_content_for_execution(&pol, &Tool::WriteFile, payload).is_none());
    }

    #[test]
    fn mask_rewrites_http_body() {
        let pol = policy(ContentMode::Mask, vec![ContentDetector::Pii]);
        let payload = r#"{"url":"https://x.test","method":"POST","body":"mail a@b.com here"}"#;

        let app = apply_content_for_execution(&pol, &Tool::HttpRequest, payload)
            .expect("mask produces an application");

        let masked = app.masked_payload.expect("mask rewrites the body");
        assert!(masked.contains("[REDACTED:Email]"));
        assert!(!masked.contains("a@b.com"));
        let v: serde_json::Value = serde_json::from_str(&masked).unwrap();
        assert_eq!(v["url"], "https://x.test");
    }
}
