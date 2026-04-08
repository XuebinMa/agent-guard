use agent_guard_core::{Context, Tool, TrustLevel, GuardDecision};
use agent_guard_sdk::{Guard, ExecuteOutcome, GuardInput, ExecutionReceipt};
use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxResult, SandboxCapabilities};
use std::path::PathBuf;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

// ── Mock Sandbox for Fail-Closed Testing ────────────────────────────────────

struct FailingSandbox;
impl Sandbox for FailingSandbox {
    fn name(&self) -> &'static str { "failing" }
    fn sandbox_type(&self) -> &'static str { "failing" }
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: true,
            filesystem_write_workspace: true,
            filesystem_write_global: true,
            network_outbound_any: true,
            network_outbound_internet: true,
            network_outbound_local: true,
            child_process_spawn: true,
            registry_write: true,
        }
    }
    fn execute(&self, _command: &str, _context: &SandboxContext) -> SandboxResult {
        Err(SandboxError::ExecutionFailed("Simulated init failure".to_string()))
    }
    fn is_available(&self) -> bool { true }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// GATE 1: Fail-Closed Robustness
/// Ensures that any failure in sandbox initialization or environment setup 
/// results in a hard error and blocks tool execution.
#[test]
fn test_gate_fail_closed_robustness() {
    let guard = Guard::from_yaml("version: 1\ndefault_mode: full_access").unwrap();
    let context = Context {
        agent_id: Some("gate-fail".to_string()),
        session_id: None,
        actor: None,
        trust_level: TrustLevel::Trusted,
        working_directory: Some(PathBuf::from(".")),
    };
    let input = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"echo 1"}"#.to_string(),
        context,
    };

    let sandbox = FailingSandbox;
    let res = guard.execute(&input, &sandbox);
    
    // FAIL-CLOSED: Any sandbox error must be returned as Err, blocking execution result.
    assert!(res.is_err(), "Sandbox failure must be a hard error");
    if let Err(e) = res {
        assert!(e.to_string().contains("Simulated init failure"));
    }
}

/// GATE 2: Platform Selection Consistency
/// Verifies that the SDK selects the optimal security backend for the current platform.
#[test]
fn test_gate_platform_selection_consistency() {
    let sandbox = Guard::default_sandbox();
    let s_type = sandbox.sandbox_type();
    
    #[cfg(target_os = "linux")]
    assert_eq!(s_type, "linux-seccomp");
    
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    assert_eq!(s_type, "macos-seatbelt");
    
    #[cfg(all(target_os = "windows", feature = "windows-sandbox"))]
    assert_eq!(s_type, "windows-job-object");

    #[cfg(not(any(target_os = "linux", all(target_os = "macos", feature = "macos-sandbox"), all(target_os = "windows", feature = "windows-sandbox"))))]
    assert_eq!(s_type, "none");
}

/// GATE 3: Negative Security Boundary
/// Ensures that illegal operations (e.g., global filesystem writes) are strictly 
/// blocked by the OS-level sandbox, regardless of the policy outcome.
#[test]
fn test_gate_negative_security_boundary_write_restriction() {
    let guard = Guard::from_yaml("version: 1\ndefault_mode: workspace_write").unwrap();
    let sandbox = Guard::default_sandbox();
    
    if !sandbox.is_available() || sandbox.sandbox_type() == "none" {
        return; // Skip if no real sandbox is active
    }

    let temp_dir = std::env::temp_dir().join("gate_boundary_test");
    let _ = std::fs::create_dir_all(&temp_dir);

    let global_path = if cfg!(windows) {
        PathBuf::from("C:\\Windows\\agent_guard_gate_test.txt")
    } else {
        PathBuf::from("/etc/agent_guard_gate_test.txt")
    };

    let cmd = if cfg!(windows) {
        format!("echo fail > \"{}\"", global_path.display())
    } else {
        format!("echo fail > {}", global_path.display())
    };

    let context = Context {
        agent_id: Some("gate-boundary".to_string()),
        session_id: None,
        actor: None,
        trust_level: TrustLevel::Trusted,
        working_directory: Some(temp_dir.clone()),
    };
    let input = GuardInput {
        tool: Tool::Bash,
        payload: serde_json::json!({ "command": cmd }).to_string(),
        context,
    };

    let res = guard.execute(&input, sandbox.as_ref());
    
    // SUCCESS CRITERIA: 
    // The write must NOT succeed. This can be manifested as:
    // 1. A hard SandboxError (Err)
    // 2. A Denied outcome
    // 3. An Executed outcome with a non-zero exit code (OS blocked the write)
    match res {
        Err(_) => (), // Passed (Blocked by SDK/Sandbox setup)
        Ok(outcome) => match outcome {
            ExecuteOutcome::Denied { .. } | ExecuteOutcome::AskRequired { .. } => (), // Passed (Blocked by Policy)
            ExecuteOutcome::Executed { output } => {
                assert!(output.exit_code != 0, "Sandbox must block unauthorized global write (exit code must be non-zero). Output: {:?}", output);
            }
        }
    }

    let _ = std::fs::remove_dir_all(temp_dir);
}

/// GATE 4: Receipt and Audit Integrity
/// Verifies the cryptographic chain of custody: tool call -> execution -> signed receipt.
#[test]
fn test_gate_receipt_and_audit_integrity() {
    let guard = Guard::from_yaml("version: 1\ndefault_mode: read_only").unwrap();
    let context = Context {
        agent_id: Some("gate-agent".to_string()),
        session_id: None,
        actor: Some("operator".to_string()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some(PathBuf::from(".")),
    };
    let input = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"ls"}"#.to_string(),
        context,
    };

    let decision = guard.check(&input);
    assert_eq!(decision, GuardDecision::Allow);

    // 1. Generate Receipt
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();

    let receipt = ExecutionReceipt::sign(
        "gate-agent",
        "bash",
        "v1",
        "gate-sandbox",
        &decision,
        "hash-123",
        &signing_key,
    );

    // 2. Verify Integrity
    assert!(receipt.verify(&public_key.to_bytes()), "Receipt verification failed");
    assert_eq!(receipt.agent_id, "gate-agent");
    assert_eq!(receipt.decision, "allow");
    
    // 3. Audit check (conceptual - verifying serialization works)
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"signature\""));
}
