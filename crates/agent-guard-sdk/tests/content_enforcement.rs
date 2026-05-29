//! S6-4b integration: content-layer enforcement wired through `Guard::check`.
//!
//! These tests only compile with the `content` feature, since the enforcement
//! stage in `evaluate()` is gated behind it.
#![cfg(feature = "content")]

use agent_guard_sdk::{Context, DecisionCode, Guard, GuardDecision, Tool};

/// Policy that allows http_request at the action layer but blocks outbound
/// content carrying secrets/PII.
const BLOCK_POLICY: &str = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
    content:
      mode: block
"#;

/// Same shape but Warn mode — content findings must not change the decision.
const WARN_POLICY: &str = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
    content:
      mode: warn
"#;

fn guard(yaml: &str) -> Guard {
    Guard::from_yaml(yaml).expect("policy parses")
}

#[test]
fn block_mode_denies_http_body_with_secret() {
    let g = guard(BLOCK_POLICY);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"token=AKIAIOSFODNN7EXAMPLE"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    match decision {
        GuardDecision::Deny { reason } => {
            assert_eq!(reason.code, DecisionCode::SensitiveContentBlocked);
            // The deny message must never echo the raw secret.
            assert!(!reason.message.contains("AKIAIOSFODNN7EXAMPLE"));
        }
        other => panic!("expected deny, got {other:?}"),
    }
}

#[test]
fn block_mode_allows_clean_http_body() {
    let g = guard(BLOCK_POLICY);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"hello world"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    assert_eq!(decision, GuardDecision::Allow);
}

#[test]
fn warn_mode_allows_even_with_secret() {
    let g = guard(WARN_POLICY);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"token=AKIAIOSFODNN7EXAMPLE"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    assert_eq!(decision, GuardDecision::Allow);
}

#[test]
fn no_content_policy_means_no_content_enforcement() {
    let yaml = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
"#;
    let g = guard(yaml);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"token=AKIAIOSFODNN7EXAMPLE"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    assert_eq!(decision, GuardDecision::Allow);
}
