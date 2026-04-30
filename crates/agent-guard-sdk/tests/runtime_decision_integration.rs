use agent_guard_sdk::{
    guard::{Guard, RuntimeOutcome},
    Context, DecisionCode, HandoffResult, RuntimeDecision, Tool, TrustLevel,
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
            request_id,
            policy_version,
            ..
        } => {
            assert!(!request_id.is_empty());
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
        RuntimeOutcome::AskForApproval {
            message, reason, ..
        } => {
            assert!(!message.is_empty(), "ask message should be set");
            assert!(!reason.message.is_empty(), "reason message should be set");
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

// Policy without URL-regex deny, so the only thing that can block the
// metadata endpoint is the DNS-level unconditional deny-list in the
// executor. Validates that baseline protection survives even when the
// user's policy forgets the well-known regex.
const POLICY_WITHOUT_URL_DENY: &str = r#"
version: 1
default_mode: workspace_write
audit:
  enabled: false
anomaly:
  enabled: false
"#;

#[test]
fn run_blocks_mutation_http_to_link_local_metadata_ip() {
    let g = Guard::from_yaml(POLICY_WITHOUT_URL_DENY).expect("guard init");
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::HttpRequest,
        payload: r#"{"method":"POST","url":"http://169.254.169.254/latest/meta-data","body":"x"}"#
            .to_string(),
        context: trusted(),
    };

    let err = g
        .run(&input, &sandbox)
        .expect_err("expected SSRF block, not execution");
    let msg = err.to_string();
    assert!(
        msg.contains("blocked address") && msg.contains("169.254"),
        "unexpected error: {msg}"
    );
}

#[test]
fn run_blocks_mutation_http_to_unspecified_ip() {
    let g = Guard::from_yaml(POLICY_WITHOUT_URL_DENY).expect("guard init");
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::HttpRequest,
        payload: r#"{"method":"POST","url":"http://0.0.0.0/","body":"x"}"#.to_string(),
        context: trusted(),
    };

    let err = g
        .run(&input, &sandbox)
        .expect_err("expected SSRF block, not execution");
    assert!(
        err.to_string().contains("blocked address"),
        "unexpected error: {err}"
    );
}

#[test]
fn run_does_not_follow_redirect_on_mutation_http() {
    let server = MockServer::start();
    let redirect_mock = server.mock(|when, then| {
        when.method(POST).path("/publish");
        then.status(302)
            .header("Location", "http://example.com/elsewhere")
            .body("");
    });

    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::HttpRequest,
        payload: format!(
            r#"{{"method":"POST","url":"{}","body":"x"}}"#,
            server.url("/publish")
        ),
        context: trusted(),
    };

    match guard().run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::Executed { output, .. } => {
            // 302 is non-2xx, so exit_code reflects the redirect response
            // itself rather than success at the final URL.
            assert_ne!(output.exit_code, 0);
            redirect_mock.assert();
        }
        other => panic!("expected Executed (with 302), got {other:?}"),
    }
}

#[test]
fn run_handoff_exposes_request_id() {
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::ReadFile,
        payload: r#"{"path":"/workspace/README.md"}"#.to_string(),
        context: trusted(),
    };

    match guard().run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::Handoff { request_id, .. } => {
            assert!(!request_id.is_empty(), "handoff request_id should be set");
        }
        other => panic!("expected Handoff, got {other:?}"),
    }
}

#[test]
fn run_denied_exposes_reason_directly() {
    // Policy denies any http_request to the EC2 metadata link-local IP via regex.
    // The check-path returns GuardDecision::Deny, which Guard::run now surfaces
    // as RuntimeOutcome::Denied carrying the DecisionReason directly (no wrapping
    // RuntimeDecision). The reason code is DENIED_BY_RULE for policy-rule denies.
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::HttpRequest,
        payload: r#"{"method":"POST","url":"http://169.254.169.254/latest/meta-data","body":"x"}"#
            .to_string(),
        context: trusted(),
    };

    match guard().run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::Denied {
            request_id, reason, ..
        } => {
            assert!(!request_id.is_empty());
            assert_eq!(reason.code, DecisionCode::DeniedByRule);
            assert!(
                !reason.message.is_empty(),
                "denied reason should carry a message"
            );
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn report_handoff_result_emits_execution_finished() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let policy = format!(
        r#"
version: 1
default_mode: workspace_write
tools:
  read_file: {{}}
audit:
  enabled: true
  output: file
  file_path: "{}"
anomaly:
  enabled: false
"#,
        audit_path.display()
    );

    let guard = Guard::from_yaml(&policy).expect("guard init");
    let sandbox = agent_guard_sandbox::NoopSandbox;
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::ReadFile,
        payload: r#"{"path":"/workspace/README.md"}"#.to_string(),
        context: trusted(),
    };

    let request_id = match guard.run(&input, &sandbox).expect("runtime run") {
        RuntimeOutcome::Handoff { request_id, .. } => request_id,
        other => panic!("expected Handoff, got {other:?}"),
    };

    guard.report_handoff_result(
        &request_id,
        HandoffResult {
            exit_code: 0,
            duration_ms: 42,
            stderr: None,
        },
    );

    // Audit-file writes are now asynchronous; dropping the Guard joins the
    // background writer thread so all pending lines are flushed to disk
    // before we inspect the file.
    drop(guard);

    let contents = std::fs::read_to_string(&audit_path).expect("read audit file");
    let execution_finished: Vec<serde_json::Value> = contents
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v.get("type").and_then(|t| t.as_str()) == Some("execution_finished"))
        .collect();

    assert_eq!(
        execution_finished.len(),
        1,
        "expected one execution_finished record, got audit file:\n{contents}"
    );
    let record = &execution_finished[0];
    assert_eq!(record["request_id"].as_str(), Some(request_id.as_str()));
    assert_eq!(record["exit_code"].as_i64(), Some(0));
    assert_eq!(record["duration_ms"].as_i64(), Some(42));
    assert_eq!(record["sandbox_type"].as_str(), Some("host-handoff"));
    assert_eq!(record["tool"].as_str(), Some("handoff"));
}
