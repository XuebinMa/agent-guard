use agent_guard_core::{Context, Tool, TrustLevel};
use agent_guard_sdk::{Guard, ExecuteOutcome};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ agent-guard Demo 2: Malicious Block (Deny Fuse)");
    println!("====================================================\n");

    let audit_path = "demo_malicious_audit.jsonl";
    let _ = fs::remove_file(audit_path);

    // 1. Setup Policy with Deny Fuse
    let yaml = format!(r#"
version: 1
default_mode: read_only
tools:
  bash:
    deny:
      - "rm -rf /"
audit:
  enabled: true
  output: file
  file_path: {}
anomaly:
  enabled: true
  deny_fuse:
    enabled: true
    threshold: 2
    window_seconds: 60
"#, audit_path);

    let guard = Guard::from_yaml(&yaml)?;
    let context = Context {
        agent_id: Some("malicious-agent".to_string()),
        session_id: Some("session-demo-2".to_string()),
        actor: Some("adversary".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(std::env::current_dir()?),
    };

    let malicious_input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"rm -rf /"}"#.to_string(),
        context: context.clone(),
    };

    // 2. First Malicious Attempt
    println!("👉 Attempt 1: Agent calls 'bash rm -rf /'");
    let res1 = guard.execute_default(&malicious_input)?;
    if let ExecuteOutcome::Denied { decision, .. } = res1 {
        println!("❌ Result: DENIED (Reason: {:?})\n", decision);
    }

    // 3. Second Malicious Attempt -> Should trigger fuse AFTER this
    println!("👉 Attempt 2: Agent calls 'bash rm -rf /' again");
    let res2 = guard.execute_default(&malicious_input)?;
    if let ExecuteOutcome::Denied { decision, .. } = res2 {
        println!("❌ Result: DENIED (Reason: {:?})\n", decision);
    }

    // 4. Third Attempt -> Agent should be LOCKED
    println!("👉 Attempt 3: Any call from this agent now");
    let normal_input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"ls"}"#.to_string(),
        context,
    };
    let res3 = guard.execute_default(&normal_input)?;
    if let ExecuteOutcome::Denied { decision, .. } = res3 {
        println!("🔒 Result: DENIED (AGENT_LOCKED)");
        println!("   The agent is now globally fused and blocked from all tool calls.");
        println!("   Internal Decision: {:?}\n", decision);
    }

    // 5. Show Audit Logs
    println!("📜 Audit Records (Last 2 lines):");
    let audit_log = fs::read_to_string(audit_path)?;
    for line in audit_log.lines().rev().take(2).collect::<Vec<_>>().into_iter().rev() {
        println!("{}", line);
    }
    println!("\n====================================================");

    let _ = fs::remove_file(audit_path);
    Ok(())
}
