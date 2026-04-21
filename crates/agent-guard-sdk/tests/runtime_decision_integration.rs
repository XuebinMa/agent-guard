use agent_guard_sdk::{
    guard::{Guard, RuntimeOutcome},
    Context, RuntimeDecision, Tool, TrustLevel,
};
use httpmock::Method::POST;
use httpmock::MockServer;

fn trusted() -> Context {
    Context {
        trust_level: TrustLevel::Trusted,
        working_directory: Some(std::env::temp_dir()),
        ..Default::default()
    }
}

const POLICY: &str = r#"
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - prefix: "echo"
    deny:
      - prefix: "rm -rf"
    ask:
      - prefix: "git push"
  read_file:
    deny_paths:
      - "/etc/**"
  write_file:
    allow_paths:
      - "/workspace/**"
  http_request:
    deny:
      - regex: "^https?://169\\.254\\.169\\.254"
audit:
  enabled: false
anomaly:
  enabled: false
"#;

fn guard() -> Guard {
    Guard::from_yaml(POLICY).expect("guard init")
}

#[test]
fn decide_returns_execute_for_allowed_bash() {
    let decision = guard().decide_tool(Tool::Bash, r#"{"command":"echo hello"}"#, trusted());
    assert_eq!(decision, RuntimeDecision::Execute);
}

#[test]
fn decide_returns_execute_for_allowed_write_file() {
    let decision = guard().decide_tool(
        Tool::WriteFile,
        r#"{"path":"/workspace/output.txt","content":"hello"}"#,
        trusted(),
    );
    assert_eq!(decision, RuntimeDecision::Execute);
}

#[test]
fn decide_returns_handoff_for_allowed_read_file() {
    let decision = guard().decide_tool(
        Tool::ReadFile,
        r#"{"path":"/workspace/README.md"}"#,
        trusted(),
    );
    assert_eq!(decision, RuntimeDecision::Handoff);
}

#[test]
fn decide_returns_execute_for_allowed_mutation_http_request() {
    let decision = guard().decide_tool(
        Tool::HttpRequest,
        r#"{"method":"POST","url":"https://api.example.com/publish","body":"{}"}"#,
        trusted(),
    );
    assert_eq!(decision, RuntimeDecision::Execute);
}

#[test]
fn decide_returns_handoff_for_non_mutation_http_request() {
    let decision = guard().decide_tool(
        Tool::HttpRequest,
        r#"{"method":"GET","url":"https://api.example.com/status"}"#,
        trusted(),
    );
    assert_eq!(decision, RuntimeDecision::Handoff);
}

#[test]
fn decide_maps_deny_and_ask_to_runtime_terms() {
    let denied = guard().decide_tool(Tool::ReadFile, r#"{"path":"/etc/passwd"}"#, trusted());
    assert!(matches!(denied, RuntimeDecision::Deny { .. }));

    let ask = guard().decide_tool(
        Tool::Bash,
        r#"{"command":"git push origin main"}"#,
        trusted(),
    );
    assert!(matches!(ask, RuntimeDecision::AskForApproval { .. }));
}

#[test]
fn run_executes_allowed_bash() {
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"echo runtime"}"#.to_string(),
        context: trusted(),
    };

    match guard().run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::Executed { output, .. } => {
            assert_eq!(output.exit_code, 0);
            assert_eq!(output.stdout.trim(), "runtime");
        }
        other => panic!("expected Executed, got {other:?}"),
    }
}

#[test]
fn run_handoffs_allowed_non_shell_tool() {
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::ReadFile,
        payload: r#"{"path":"/workspace/README.md"}"#.to_string(),
        context: trusted(),
    };

    match guard().run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::Handoff {
            decision,
            policy_version,
            ..
        } => {
            assert_eq!(decision, RuntimeDecision::Handoff);
            assert!(!policy_version.is_empty());
        }
        other => panic!("expected Handoff, got {other:?}"),
    }
}

#[test]
fn run_maps_ask_to_ask_for_approval() {
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"git push origin main"}"#.to_string(),
        context: trusted(),
    };

    match guard().run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::AskForApproval { decision, .. } => {
            assert!(matches!(decision, RuntimeDecision::AskForApproval { .. }));
        }
        other => panic!("expected AskForApproval, got {other:?}"),
    }
}

#[test]
fn run_executes_allowed_mutation_http_request() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/publish").body("payload");
        then.status(202).body("accepted");
    });

    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::HttpRequest,
        payload: format!(
            r#"{{"method":"POST","url":"{}","body":"payload"}}"#,
            server.url("/publish")
        ),
        context: trusted(),
    };

    match guard().run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::Executed { output, .. } => {
            assert_eq!(output.exit_code, 0);
            assert_eq!(output.stdout, "accepted");
            mock.assert();
        }
        other => panic!("expected Executed, got {other:?}"),
    }
}
