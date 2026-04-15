use agent_guard_core::{Context, DecisionCode, GuardDecision, Tool, TrustLevel};
use agent_guard_sandbox::NoopSandbox;
use agent_guard_sdk::{ExecuteOutcome, Guard, GuardInput};
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Duration;

// ── Tests ───────────────────────────────────────────────────────────────────

/// SCENARIO 1: Identity Confusion & Locking Boundaries
#[tokio::test]
async fn test_stress_security_identity_isolation() {
    let yaml = r#"
version: 1
default_mode: read_only
tools:
  bash:
    deny: ["restricted"]
anomaly:
  enabled: true
  deny_fuse: { enabled: true, threshold: 2, window_seconds: 60 }
"#;
    let guard = Guard::from_yaml(yaml).unwrap();
    let _sandbox = NoopSandbox;

    let actors = vec!["user-1", "user-1 ", "USER-1", "user-1\n"];

    for actor in actors {
        let context = Context {
            actor: Some(actor.to_string()),
            agent_id: Some("agent-1".to_string()),
            trust_level: TrustLevel::Trusted,
            ..Default::default()
        };
        let input = GuardInput {
            tool: Tool::Bash,
            payload: r#"{"command":"restricted"}"#.to_string(),
            context,
        };

        let res1 = guard.execute(&input, &_sandbox).unwrap();
        assert!(
            matches!(res1, ExecuteOutcome::Denied { decision: GuardDecision::Deny { reason, .. }, .. } if reason.code == DecisionCode::DeniedByRule)
        );

        let res2 = guard.execute(&input, &_sandbox).unwrap();
        assert!(
            matches!(res2, ExecuteOutcome::Denied { decision: GuardDecision::Deny { reason, .. }, .. } if reason.code == DecisionCode::DeniedByRule)
        );

        let res3 = guard.execute(&input, &_sandbox).unwrap();
        assert!(
            matches!(res3, ExecuteOutcome::Denied { decision: GuardDecision::Deny { reason, .. }, .. } if reason.code == DecisionCode::AgentLocked),
            "Actor '{}' should be locked",
            actor
        );
    }
}

/// SCENARIO 2: Reload + Fuse Cross-Version Race
#[tokio::test]
async fn test_stress_security_reload_fuse_race() {
    let guard = Arc::new(Guard::from_yaml("version: 1\ndefault_mode: read_only\nanomaly:\n  enabled: true\n  deny_fuse: { enabled: true, threshold: 2, window_seconds: 60 }").unwrap());
    let actor = "race-actor";

    let g_reload = guard.clone();
    let reload_handle = tokio::spawn(async move {
        for i in 0..100 {
            // Keep threshold low to ensure lock, but change version
            let yaml = format!(
                r#"
version: {}
default_mode: read_only
anomaly:
  enabled: true
  deny_fuse: {{ enabled: true, threshold: 2, window_seconds: 60 }}
"#,
                i + 100
            );
            let _ = g_reload.reload_from_yaml(&yaml);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let g_check = guard.clone();
    let check_handle = tokio::spawn(async move {
        let mut locked_at_version = None;
        for _ in 0..1000 {
            let context = Context {
                actor: Some(actor.to_string()),
                ..Default::default()
            };
            let input = GuardInput {
                tool: Tool::Bash,
                payload: r#"{"command":"rm"}"#.to_string(),
                context,
            };

            let res = g_check.execute(&input, &NoopSandbox).unwrap();
            if let ExecuteOutcome::Denied {
                decision,
                policy_version,
                ..
            } = res
            {
                if let GuardDecision::Deny { reason, .. } = decision {
                    if reason.code == DecisionCode::AgentLocked {
                        locked_at_version = Some(policy_version);
                        break;
                    }
                }
            }
            tokio::task::yield_now().await;
        }
        locked_at_version
    });

    let result = tokio::join!(reload_handle, check_handle);
    let locked_version = result.1.expect("Check handle panicked");
    let version =
        locked_version.expect("Actor should eventually be locked under constant reloading");
    println!("👉 Actor locked under policy version: {}", version);
}

/// SCENARIO 3: Priority Consistency (Locked > Anomaly > Rule)
#[tokio::test]
async fn test_stress_security_priority_consistency() {
    let yaml = r#"
version: 1
default_mode: read_only
tools:
  bash: { deny: ["restricted"] }
anomaly:
  enabled: true
  rate_limit: { max_calls: 2, window_seconds: 60 }
  deny_fuse: { enabled: true, threshold: 2, window_seconds: 60 }
"#;
    let guard = Guard::from_yaml(yaml).unwrap();
    let actor = "priority-actor";
    let sandbox = NoopSandbox;

    let context = Context {
        actor: Some(actor.to_string()),
        ..Default::default()
    };
    let input_restricted = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"restricted"}"#.to_string(),
        context,
    };

    guard.execute(&input_restricted, &sandbox).unwrap();
    guard.execute(&input_restricted, &sandbox).unwrap();

    let res = guard.execute(&input_restricted, &sandbox).unwrap();
    if let ExecuteOutcome::Denied { decision, .. } = res {
        if let GuardDecision::Deny { reason, .. } = decision {
            assert_eq!(
                reason.code,
                DecisionCode::AgentLocked,
                "Priority failure: AGENT_LOCKED must come first"
            );
        }
    }
}

/// SCENARIO 4: 3-Way Consistency (Decision == Audit == Receipt)
#[tokio::test]
async fn test_stress_security_consistency_triad() {
    use agent_guard_sdk::ExecutionReceipt;
    let guard = Guard::from_yaml("version: 1\ndefault_mode: read_only").unwrap();
    let mut csprng = StdRng::from_entropy();
    let signing_key = SigningKey::generate(&mut csprng);

    let context = Context {
        agent_id: Some("agent-triad".to_string()),
        actor: Some("user-triad".to_string()),
        ..Default::default()
    };
    let input = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"ls"}"#.to_string(),
        context,
    };

    let res = guard.execute(&input, &NoopSandbox).unwrap();
    let ExecuteOutcome::Executed { policy_version, .. } = res else {
        panic!("Should allow")
    };

    let decision = guard.check(&input);
    let receipt = ExecutionReceipt::sign(
        "agent-triad",
        "bash",
        &policy_version,
        "noop",
        &decision,
        "h123",
        &signing_key,
    );

    assert!(!policy_version.is_empty());
    assert_eq!(receipt.policy_version, policy_version);
    assert_eq!(receipt.agent_id, "agent-triad");
    assert_eq!(receipt.decision, "allow");
}

/// SCENARIO 5: Webhook Failure Resilience
#[tokio::test]
async fn test_stress_security_webhook_resilience() {
    use httpmock::prelude::*;
    let server = match std::panic::catch_unwind(MockServer::start) {
        Ok(server) => server,
        Err(_) => {
            eprintln!("Skipping webhook resilience test: local listener startup is not permitted");
            return;
        }
    };

    server.mock(|when, then| {
        when.method(POST).path("/fail");
        then.status(500);
    });

    let yaml = format!(
        r#"
version: 1
default_mode: read_only
audit:
  enabled: true
  webhook_url: "http://{}/fail"
anomaly:
  enabled: true
  deny_fuse: {{ enabled: true, threshold: 2, window_seconds: 60 }}
"#,
        server.address()
    );

    let guard = Guard::from_yaml(&yaml).unwrap();
    let context = Context {
        actor: Some("victim".to_string()),
        ..Default::default()
    };
    let input = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"rm"}"#.to_string(),
        context,
    };

    guard.execute(&input, &NoopSandbox).unwrap();
    guard.execute(&input, &NoopSandbox).unwrap();

    let res = guard.execute(&input, &NoopSandbox).unwrap();
    if let ExecuteOutcome::Denied { decision, .. } = res {
        if let GuardDecision::Deny { reason, .. } = decision {
            assert_eq!(
                reason.code,
                DecisionCode::AgentLocked,
                "Local locking failed due to webhook error?"
            );
        }
    }
}
