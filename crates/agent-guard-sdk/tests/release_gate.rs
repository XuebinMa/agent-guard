use agent_guard_core::{Context, Tool, TrustLevel};
use agent_guard_sdk::{Guard, ExecuteOutcome, GuardInput};
use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxResult, SandboxCapabilities};
use std::path::PathBuf;

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

#[test]
fn test_gate_platform_selection_consistency() {
    let sandbox = Guard::default_sandbox();
    let s_type = sandbox.sandbox_type();
    
    #[cfg(target_os = "linux")]
    assert_eq!(s_type, "linux-seccomp");
    
    #[cfg(feature = "macos-sandbox")]
    assert_eq!(s_type, "macos-seatbelt");
    
    #[cfg(feature = "windows-sandbox")]
    assert_eq!(s_type, "windows-job-object");
}

#[test]
fn test_gate_negative_security_boundary_write_restriction() {
    let guard = Guard::from_yaml("version: 1\ndefault_mode: workspace_write").unwrap();
    let sandbox = Guard::default_sandbox();
    
    if !sandbox.is_available() || sandbox.sandbox_type() == "none" {
        return; // Skip if no real sandbox is active
    }

    let temp_dir = std::env::temp_dir().join("gate_boundary_test");
    let _ = std::fs::create_dir_all(&temp_dir);

    // Try to write to a path that SHOULD be restricted by the OS sandbox
    // even if the policy incorrectly allowed it (though here we use workspace_write)
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

    let res = guard.execute(&input, sandbox.as_ref()).unwrap();
    if let ExecuteOutcome::Executed { output } = res {
        // The sandbox should have intercepted this write
        assert!(output.exit_code != 0, "Sandbox must block unauthorized global write. Output: {:?}", output);
    }

    let _ = std::fs::remove_dir_all(temp_dir);
}
