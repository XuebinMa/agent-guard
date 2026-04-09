use agent_guard_core::{DecisionCode, GuardDecision};
use agent_guard_sdk::{Guard, GuardInput};

fn main() {
    // 1. Load policy with anomaly detection (limit 5 calls per minute)
    let yaml = r#"
version: 1
default_mode: workspace_write
anomaly:
  enabled: true
  rate_limit:
    window_seconds: 60
    max_calls: 5
"#;
    let guard = Guard::from_yaml(yaml).unwrap();
    let input = GuardInput::new(agent_guard_core::Tool::Bash, r#"{"command":"ls"}"#);

    // 2. Perform tool calls rapidly
    for i in 1..=10 {
        let decision = guard.check(&input);
        println!("Call #{}: is_allowed = {}", i, decision.is_allowed());

        if i > 5 {
            // The 6th call should trigger the anomaly detection
            match decision {
                GuardDecision::Deny { reason } => {
                    assert_eq!(reason.code, DecisionCode::AnomalyDetected);
                    println!("  Expected Deny: {}", reason.message);
                }
                _ => panic!("Call #{} expected Deny, but was allowed", i),
            }
        } else {
            assert!(decision.is_allowed());
        }
    }

    println!("Anomaly detection integration test PASSED!");
}
