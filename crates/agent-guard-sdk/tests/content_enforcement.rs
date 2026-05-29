//! S6-4b integration: content-layer enforcement wired through `Guard::check`.
//!
//! These tests only compile with the `content` feature, since the enforcement
//! stage in `evaluate()` is gated behind it.
#![cfg(feature = "content")]

use agent_guard_sdk::{
    guard::ExecuteOutcome, Context, DecisionCode, Guard, GuardDecision, GuardInput, Tool,
    TrustLevel,
};

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

/// End-to-end: Mask mode rewrites the executed WriteFile payload, so the file
/// on disk contains the redaction placeholder rather than the raw secret.
#[test]
fn mask_mode_writes_redacted_file_on_execution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        r#"
version: 1
default_mode: workspace_write
tools:
  write_file:
    mode: workspace_write
    allow_paths:
      - "{}/**"
    content:
      mode: mask
"#,
        dir.path().display()
    );
    let g = Guard::from_yaml(&yaml).expect("policy parses");

    let target = dir.path().join("out.txt");
    let inp = GuardInput {
        tool: Tool::WriteFile,
        payload: format!(
            r#"{{"path":"{}","content":"token AKIAIOSFODNN7EXAMPLE end"}}"#,
            target.display()
        ),
        context: Context {
            trust_level: TrustLevel::Trusted,
            working_directory: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
    };

    let sandbox = agent_guard_sandbox::NoopSandbox;
    match g.execute(&inp, &sandbox).expect("no sandbox error") {
        ExecuteOutcome::Executed { .. } => {
            let contents = std::fs::read_to_string(&target).expect("read target");
            assert!(contents.contains("[REDACTED:AWS Access Key]"));
            assert!(!contents.contains("AKIAIOSFODNN7EXAMPLE"));
        }
        other => panic!("expected Executed, got {other:?}"),
    }
}
