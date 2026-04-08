use agent_guard_core::{Context, Tool, GuardDecision, DecisionCode, TrustLevel};
use agent_guard_sdk::{Guard, ExecuteOutcome, get_metrics};
use agent_guard_sandbox::NoopSandbox;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_e2e_full_chain_allow() {
    let audit_path = "audit_e2e_allow.jsonl";
    let _ = fs::remove_file(audit_path);

    let yaml = format!(r#"
version: 1
default_mode: read_only
audit:
  enabled: true
  output: file
  file_path: {}
"#, audit_path);

    let guard = Guard::from_yaml(&yaml).unwrap();
    let sandbox = NoopSandbox;
    let context = Context {
        agent_id: Some("agent-allow".to_string()),
        session_id: Some("session-1".to_string()),
        actor: Some("user-1".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(PathBuf::from(".")),
    };

    let input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"echo hello"}"#.to_string(),
        context,
    };

    // 1. Execute
    let res = guard.execute(&input, &sandbox).unwrap();
    
    // 2. Verify Output
    if let ExecuteOutcome::Executed { output, .. } = res {
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.contains("hello"));
    } else {
        panic!("Execution should have succeeded");
    }

    // 3. Verify Audit
    let audit_content = fs::read_to_string(audit_path).unwrap();
    assert!(audit_content.contains("\"decision\":\"allow\""));
    assert!(audit_content.contains("\"agent_id\":\"agent-allow\""));

    // 4. Verify Metrics
    let metrics = get_metrics();
    // We can't easily reset global metrics in a test, but we can check if it increased.
    // However, since it's a global singleton, other tests might interfere if run in parallel.
    // In a real E2E environment, we'd check the delta or use a dedicated registry.
    // For this test, we just ensure it's accessible.
    let labels = agent_guard_sdk::metrics::DecisionLabels {
        agent_id: "agent-allow".to_string(),
        tool: "bash".to_string(),
        outcome: "allow".to_string(),
    };
    assert!(metrics.decision_total.get_or_create(&labels).get() >= 1);

    let _ = fs::remove_file(audit_path);
}

#[test]
fn test_e2e_full_chain_deny() {
    let audit_path = "audit_e2e_deny.jsonl";
    let _ = fs::remove_file(audit_path);

    let yaml = format!(r#"
version: 1
default_mode: read_only
tools:
  bash:
    deny:
      - "ls /restricted"
audit:
  enabled: true
  output: file
  file_path: {}
"#, audit_path);

    let guard = Guard::from_yaml(&yaml).unwrap();
    let sandbox = NoopSandbox;
    let context = Context {
        agent_id: Some("agent-deny".to_string()),
        session_id: Some("session-2".to_string()),
        actor: Some("user-2".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(PathBuf::from(".")),
    };

    let input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"ls /restricted"}"#.to_string(),
        context,
    };

    // 1. Execute (Should be denied)
    let res = guard.execute(&input, &sandbox).unwrap();
    
    if let ExecuteOutcome::Denied { decision, .. } = res {
        if let GuardDecision::Deny { reason } = decision {
            assert_eq!(reason.code, DecisionCode::DeniedByRule);
        } else {
            panic!("Should be a Deny decision");
        }
    } else {
        panic!("Execution should have been denied");
    }

    // 2. Verify Audit
    let audit_content = fs::read_to_string(audit_path).unwrap();
    assert!(audit_content.contains("\"decision\":\"deny\""));
    assert!(audit_content.contains("DENIED_BY_RULE"));

    // 3. Verify Metrics
    let metrics = get_metrics();
    let labels = agent_guard_sdk::metrics::DecisionLabels {
        agent_id: "agent-deny".to_string(),
        tool: "bash".to_string(),
        outcome: "deny".to_string(),
    };
    assert!(metrics.decision_total.get_or_create(&labels).get() >= 1);

    let _ = fs::remove_file(audit_path);
}

#[test]
fn test_e2e_anomaly_fuse() {
    let yaml = r#"
version: 1
default_mode: read_only
tools:
  bash:
    deny:
      - "restricted"
anomaly:
  enabled: true
  deny_fuse:
    enabled: true
    threshold: 2
    window_seconds: 60
"#;

    let guard = Guard::from_yaml(yaml).unwrap();
    let sandbox = NoopSandbox;
    let context = Context {
        agent_id: Some("agent-fuse".to_string()),
        session_id: Some("session-3".to_string()),
        actor: Some("actor-fuse".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(PathBuf::from(".")),
    };

    let input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"restricted"}"#.to_string(),
        context: context.clone(),
    };

    // 1. Trigger first deny
    let res1 = guard.execute(&input, &sandbox).unwrap();
    if let ExecuteOutcome::Denied { decision, .. } = res1 {
        if let GuardDecision::Deny { reason } = decision {
            assert_eq!(reason.code, DecisionCode::DeniedByRule);
        }
    }

    // 2. Trigger second deny -> will trigger fuse internally AFTER this check
    let res2 = guard.execute(&input, &sandbox).unwrap();
    if let ExecuteOutcome::Denied { decision, .. } = res2 {
        if let GuardDecision::Deny { reason } = decision {
            assert_eq!(reason.code, DecisionCode::DeniedByRule);
        }
    }

    // 3. Subsequent call should be short-circuited (AgentLocked)
    let res3 = guard.execute(&input, &sandbox).unwrap();
    if let ExecuteOutcome::Denied { decision, .. } = res3 {
        if let GuardDecision::Deny { reason } = decision {
            assert_eq!(reason.code, DecisionCode::AgentLocked);
        } else {
            panic!("Should be AgentLocked");
        }
    } else {
        panic!("Call 3 should be denied as AgentLocked");
    }

    // 4. Verify Metrics
    let metrics = get_metrics();
    let labels = agent_guard_sdk::metrics::ToolLabels {
        agent_id: "agent-fuse".to_string(),
        tool: "bash".to_string(),
    };
    assert!(metrics.anomaly_triggered_total.get_or_create(&labels).get() >= 1);
}

#[test]
fn test_e2e_provenance_receipt() {
    use agent_guard_sdk::ExecutionReceipt;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let guard = Guard::from_yaml("version: 1\ndefault_mode: read_only").unwrap();
    let context = Context {
        agent_id: Some("agent-receipt".to_string()),
        session_id: Some("session-4".to_string()),
        actor: Some("actor-4".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(PathBuf::from(".")),
    };

    let input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"ls"}"#.to_string(),
        context,
    };

    let decision = guard.check(&input);
    
    // Generate Receipt
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();

    let receipt = ExecutionReceipt::sign(
        "agent-receipt",
        "bash",
        "v1",
        "noop",
        &decision,
        "hash",
        &signing_key,
    );

    assert_eq!(receipt.agent_id, "agent-receipt");
    assert_eq!(receipt.decision, "allow");
    
    // Verify
    assert!(receipt.verify(&public_key.to_bytes()));

    // Tamper
    let mut tampered = receipt.clone();
    tampered.decision = "deny".to_string();
    assert!(!tampered.verify(&public_key.to_bytes()));
}
