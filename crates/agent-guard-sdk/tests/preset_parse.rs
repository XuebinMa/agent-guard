//! Regression guard for the shipped outbound preset.
//!
//! The preset is an advertised, copy-able artifact, but is otherwise
//! untested — a typo in its YAML would ship silently. This loads the real
//! file and asserts it parses and that the content-layer wiring is present.
//! Content parsing is feature-independent (the schema lives in core), so this
//! runs on the default build.

use agent_guard_core::{ContentDetector, ContentMode, PolicyEngine, Tool};

fn preset_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../presets/coding-agent-outbound.yaml")
}

#[test]
fn outbound_preset_parses() {
    PolicyEngine::from_yaml_file(preset_path()).expect("outbound preset should parse");
}

#[test]
fn outbound_preset_blocks_http_body_content() {
    let engine = PolicyEngine::from_yaml_file(preset_path()).expect("preset parses");

    let policy = engine
        .content_policy(&Tool::HttpRequest)
        .expect("http_request has a content policy");

    assert_eq!(policy.mode, ContentMode::Block);
    assert_eq!(
        policy.detect,
        vec![ContentDetector::Secrets, ContentDetector::Pii]
    );
}

#[test]
fn outbound_preset_warns_on_write_file_content() {
    let engine = PolicyEngine::from_yaml_file(preset_path()).expect("preset parses");

    let policy = engine
        .content_policy(&Tool::WriteFile)
        .expect("write_file has a content policy");

    assert_eq!(policy.mode, ContentMode::Warn);
}

/// End-to-end: with the `content` feature, the real preset denies a secret in
/// an outbound HTTP body (the URL itself is to an arbitrary, allowed host).
#[cfg(feature = "content")]
#[test]
fn outbound_preset_denies_secret_in_http_body() {
    use agent_guard_core::DecisionCode;
    use agent_guard_sdk::{Context, Guard, GuardDecision, Tool as SdkTool};

    let guard = Guard::from_yaml_file(preset_path()).expect("preset loads");
    let payload =
        r#"{"url":"https://api.example.test","method":"POST","body":"key AKIAIOSFODNN7EXAMPLE"}"#;

    match guard.check_tool(SdkTool::HttpRequest, payload, Context::default()) {
        GuardDecision::Deny { reason } => {
            assert_eq!(reason.code, DecisionCode::SensitiveContentBlocked);
            assert!(!reason.message.contains("AKIAIOSFODNN7EXAMPLE"));
        }
        other => panic!("expected deny, got {other:?}"),
    }
}
