use agent_guard_core::{Context, Tool, GuardDecision};
use agent_guard_sdk::{Guard, ExecutionReceipt};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup crypto keys (In production, these come from secure storage)
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();

    // 2. Initialize Guard
    let yaml = "version: 1\ndefault_mode: read_only\n";
    let guard = Guard::from_yaml(yaml)?;

    // 3. Create a Tool Call context
    let context = Context {
        agent_id: Some("enterprise-agent-007".to_string()),
        session_id: Some("session-abc".to_string()),
        actor: Some("privileged-operator".to_string()),
        trust_level: agent_guard_core::TrustLevel::Trusted,
        working_directory: None,
    };

    println!("Evaluating tool call: bash ls");
    let decision = guard.check_tool(Tool::Bash, r#"{"command":"ls"}"#, context.clone());

    // 4. Generate a Signed Receipt (Provenance)
    let receipt = ExecutionReceipt::sign(
        context.agent_id.as_deref().unwrap_or("unknown"),
        "bash",
        "policy-v1-sha256", // In real use, this is the policy's content hash
        "linux-seccomp",    // In real use, this is the active sandbox type
        &decision,
        "sha256:command-content-hash",
        &signing_key,
    );

    println!("\n--- Execution Receipt (Signed) ---");
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    println!("-----------------------------------");

    // 5. Verification
    let is_valid = receipt.verify(&public_key.to_bytes());
    println!("\nVerification status: {}", if is_valid { "✅ VALID" } else { "❌ INVALID" });

    Ok(())
}
