use agent_guard_core::{Context, Tool, TrustLevel};
use agent_guard_sdk::{Guard, ExecuteOutcome, get_metrics, ExecutionReceipt};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ agent-guard Demo 1: Happy Path (Standard Execution)");
    println!("====================================================\n");

    let audit_path = "demo_happy_audit.jsonl";
    let _ = fs::remove_file(audit_path);

    // 1. Setup Policy
    let yaml = format!(r#"
version: 1
default_mode: read_only
audit:
  enabled: true
  output: file
  file_path: {}
"#, audit_path);

    let guard = Guard::from_yaml(&yaml)?;
    let context = Context {
        agent_id: Some("happy-agent".to_string()),
        session_id: Some("session-demo-1".to_string()),
        actor: Some("demo-user".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(std::env::current_dir()?),
    };

    // 2. Perform Tool Call
    println!("👉 Action: Agent calls 'bash echo hello_agent_guard'");
    let input = agent_guard_sdk::GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"echo hello_agent_guard"}"#.to_string(),
        context,
    };

    let res = guard.execute_default(&input)?;

    // 3. Display Result
    if let ExecuteOutcome::Executed { output, .. } = res {
        println!("✅ Status: EXECUTED");
        println!("📝 Stdout: {}", output.stdout.trim());
        println!("🔢 Exit Code: {}\n", output.exit_code);
    }

    // 4. Show Audit Log
    println!("📜 Audit Record (First Line):");
    let audit_log = fs::read_to_string(audit_path)?;
    println!("{}", audit_log.lines().next().unwrap_or(""));
    println!();

    // 5. Show Metrics
    let metrics = get_metrics();
    let labels = agent_guard_sdk::metrics::DecisionLabels {
        agent_id: "happy-agent".to_string(),
        tool: "bash".to_string(),
        outcome: "allow".to_string(),
    };
    let count = metrics.decision_total.get_or_create(&labels).get();
    println!("📊 Metric: agent_guard_decision_total{{outcome='allow', agent_id='happy-agent'}} = {}\n", count);

    // 6. Generate Signed Receipt
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let receipt = ExecutionReceipt::sign(
        "happy-agent",
        "bash",
        "v1",
        "auto-detected",
        &agent_guard_core::GuardDecision::Allow,
        "sha256:...",
        &signing_key,
    );
    println!("📜 Signed Receipt (Provenance):");
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    println!("\n====================================================");

    let _ = fs::remove_file(audit_path);
    Ok(())
}
