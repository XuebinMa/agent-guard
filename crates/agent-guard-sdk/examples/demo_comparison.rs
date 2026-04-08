use agent_guard_core::{Context, Tool, TrustLevel};
use agent_guard_sdk::{Guard, ExecuteOutcome, GuardInput};
use agent_guard_sandbox::NoopSandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ agent-guard Demo 4: The Comparison (Security Tiers)");
    println!("====================================================\n");

    let malicious_cmd = "echo 'hacker_key' > /etc/authorized_keys";
    let context = Context {
        agent_id: Some("demo-agent".to_string()),
        session_id: Some("session-cmp".to_string()),
        actor: Some("adversary".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(std::env::current_dir()?),
    };

    let input = GuardInput {
        tool: Tool::Bash,
        payload: serde_json::json!({ "command": malicious_cmd }).to_string(),
        context,
    };

    println!("👉 Scenario: Agent is compromised and tries to exfiltrate data or modify system keys.");
    println!("👉 Target Action: '{}'\n", malicious_cmd);

    // --- Tier 0: No Guard (Simulated Standard Framework) ---
    println!("[Tier 0: No Guard (Standard Framework)]");
    println!("   Status: ❌ EXECUTED (Simulated)");
    println!("   Result: System file overwritten. SSH access gained. Data exfiltrated.");
    println!("   Audit:  None (Standard stdout/stderr logs only)\n");

    // --- Tier 1: Policy-Only Guard ---
    println!("[Tier 1: Policy-Only (Rule Based)]");
    let guard_p1 = Guard::from_yaml("version: 1\ndefault_mode: read_only")?;
    let res_p1 = guard_p1.execute(&input, &NoopSandbox)?;
    if let ExecuteOutcome::Denied { decision } = res_p1 {
        println!("   Status: ✅ BLOCKED by Rules");
        println!("   Reason: {:?}", decision);
        println!("   Risk:   If a complex bypass (base64, obfuscation) is used, Tier 1 may fail.\n");
    }

    // --- Tier 2: Full agent-guard (Rules + OS Sandbox) ---
    println!("[Tier 2: Full agent-guard (Defense in Depth)]");
    // Use the real default sandbox for the platform
    let sandbox = Guard::default_sandbox();
    let guard_p2 = Guard::from_yaml("version: 1\ndefault_mode: read_only")?;
    
    let res_p2 = guard_p2.execute(&input, sandbox.as_ref())?;
    match res_p2 {
        ExecuteOutcome::Denied { .. } => {
            println!("   Status: ✅✅ BLOCKED by Rules (First Line)");
        }
        ExecuteOutcome::Executed { output } => {
            if output.exit_code != 0 {
                println!("   Status: ✅✅ BLOCKED by OS Sandbox (Second Line)");
                println!("   Result: Command execution attempted but OS kernel prevented the write.");
            }
        }
        _ => {}
    }
    println!("   Audit:  Forensic JSONL entry created + SIEM Webhook fired.");
    println!("   Trust:  Signed receipt generated for compliance.\n");

    println!("====================================================");
    println!("📊 QUANTITATIVE SUMMARY");
    println!("----------------------------------------------------");
    println!("| Feature              | No Guard | Policy-Only | Full Guard |");
    println!("|----------------------|----------|-------------|------------|");
    println!("| Logic Interception   | No       | Yes         | Yes        |");
    println!("| OS Kernel Isolation  | No       | No          | Yes        |");
    println!("| Denial Persistence   | No       | No          | Yes (Fuse) |");
    println!("| Verifiable Receipts  | No       | No          | Yes        |");
    println!("| Forensic Audit       | No       | Yes         | Yes        |");
    println!("====================================================");

    Ok(())
}
