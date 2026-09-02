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

#[test]
fn outbound_preset_governs_recognized_and_conservative_git_push_candidates() {
    use agent_guard_sdk::{Context, Guard, GuardDecision, Tool as SdkTool, TrustLevel};

    let guard = Guard::from_yaml_file(preset_path()).expect("preset loads");
    let context = Context {
        trust_level: TrustLevel::Trusted,
        working_directory: Some(std::env::temp_dir()),
        ..Default::default()
    };

    for command in [
        "/usr/bin/git push origin main",
        "env git push origin main",
        "stdbuf -o0 git push origin main",
        "setsid git push origin main",
        r#""git" push origin main"#,
        r#"g""it push origin main"#,
        r#"g\it push origin main"#,
        "git -C /workspace push origin main",
        "git-push origin main",
        "git push --force-if-includes origin main",
        "git push --delete origin old-branch",
        "git push origin :old-branch",
        "git send-pack origin main",
        "git-send-pack origin main",
        "firejail git push origin main",
    ] {
        let payload = serde_json::json!({ "command": command }).to_string();
        let decision = guard.check_tool(SdkTool::Bash, payload, context.clone());
        match decision {
            GuardDecision::AskUser { message, reason } => {
                assert!(
                    message.contains("origin"),
                    "preview missing remote: {message}"
                );
                assert!(
                    reason
                        .details()
                        .and_then(|details| details.get("git_push_intents"))
                        .is_some(),
                    "structured push preview missing from {reason:?}"
                );
                if command.contains("send-pack") {
                    assert!(
                        message.contains("git send-pack"),
                        "send-pack preview lost the actual command: {message}"
                    );
                }
                if command.starts_with("firejail") {
                    assert!(
                        message.contains("conservative argv candidate"),
                        "embedded preview must describe its uncertainty: {message}"
                    );
                }
            }
            other => panic!("preset must ask for `{command}`, got {other:?}"),
        }
    }

    for command in [
        "grep -r 'git push --force' src",
        "echo 'git push origin main'",
    ] {
        let payload = serde_json::json!({ "command": command }).to_string();
        let decision = guard.check_tool(SdkTool::Bash, payload, context.clone());
        assert!(
            matches!(decision, GuardDecision::Allow),
            "a combined quoted data token must not become a Git candidate: `{command}`"
        );
    }

    for command in [
        "env git push -f origin main",
        "stdbuf -o0 git push --force origin main",
        "setsid git push --force origin main",
        r#""git" push --force origin main"#,
        "git -C /workspace push origin main --force-with-lease",
        "git push --mirror origin",
        "git send-pack --force origin main",
        "git-send-pack --mirror origin",
        "firejail git push --force origin main",
    ] {
        let payload = serde_json::json!({ "command": command }).to_string();
        let decision = guard.check_tool(SdkTool::Bash, payload, context.clone());
        assert!(
            matches!(decision, GuardDecision::Deny { .. }),
            "preset must deny destructive `{command}`, got {decision:?}"
        );
    }
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
            assert_eq!(reason.code(), DecisionCode::SensitiveContentBlocked);
            assert!(!reason.message().contains("AKIAIOSFODNN7EXAMPLE"));
        }
        other => panic!("expected deny, got {other:?}"),
    }
}
