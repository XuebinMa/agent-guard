//! Cross-platform parity integration tests.
//! Verifies UCM (Unified Capability Model) behavior across all platforms.

use agent_guard_sdk::{
    guard::{ExecuteOutcome, Guard},
    Context, GuardInput, Sandbox, Tool, TrustLevel,
};
use std::path::PathBuf;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn get_active_sandbox() -> Box<dyn Sandbox> {
    #[cfg(target_os = "linux")]
    return Box::new(agent_guard_sandbox::SeccompSandbox::new());

    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    return Box::new(agent_guard_sandbox::SeatbeltSandbox);

    #[cfg(all(target_os = "windows", feature = "windows-sandbox"))]
    return Box::new(agent_guard_sandbox::JobObjectSandbox);

    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "macos", feature = "macos-sandbox"),
        all(target_os = "windows", feature = "windows-sandbox")
    )))]
    return Box::new(agent_guard_sandbox::NoopSandbox);
}

fn input(command: &str, working_dir: PathBuf) -> GuardInput {
    GuardInput {
        tool: Tool::Bash,
        payload: serde_json::json!({ "command": command }).to_string(),
        context: Context {
            agent_id: Some("test-agent".to_string()),
            session_id: Some("session-1".to_string()),
            actor: Some("test-actor".to_string()),
            trust_level: TrustLevel::Trusted,
            working_directory: Some(working_dir),
        },
    }
}

// ── Parity Tests ────────────────────────────────────────────────────────────

#[test]
fn test_parity_filesystem_write_workspace() {
    let sandbox = get_active_sandbox();
    if !sandbox.is_available() {
        return;
    }
    let caps = sandbox.capabilities();

    if !caps.filesystem_write_workspace {
        return; // Skip if capability not claimed
    }

    let temp_dir = std::env::temp_dir().join("agent_guard_parity_ws");
    let _ = std::fs::create_dir_all(&temp_dir);

    let guard = Guard::from_yaml("version: 1\ndefault_mode: workspace_write").unwrap();
    let target_file = temp_dir.join("test.txt");
    let cmd = if cfg!(windows) {
        format!("echo test > \"{}\"", target_file.display())
    } else {
        format!("echo test > {}", target_file.display())
    };

    let res = guard.execute(&input(&cmd, temp_dir.clone()), sandbox.as_ref());
    assert!(res.is_ok(), "Sandbox execution should not fail");

    if let ExecuteOutcome::Executed { output, .. } = res.unwrap() {
        assert_eq!(
            output.exit_code, 0,
            "Write to workspace should succeed. Stderr: {}",
            output.stderr
        );
        assert!(target_file.exists(), "File should have been created");
    }

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_parity_filesystem_write_global() {
    let sandbox = get_active_sandbox();
    let caps = sandbox.capabilities();

    if caps.filesystem_write_global {
        return; // Only test restriction
    }

    let temp_dir = std::env::temp_dir().join("agent_guard_parity_global_write");
    let _ = std::fs::create_dir_all(&temp_dir);

    let guard = Guard::from_yaml("version: 1\ndefault_mode: workspace_write").unwrap();

    // Attempt to write to a "global" path (outside workspace)
    // On Windows, we use C:\Windows\test.txt (which requires Low-IL restriction)
    // On Unix, we try /usr/bin/test.txt or similar if possible, or just a sibling of temp_dir
    let global_path = if cfg!(windows) {
        PathBuf::from("C:\\Windows\\agent_guard_parity_test.txt")
    } else {
        PathBuf::from("/etc/agent_guard_parity_test.txt")
    };

    let cmd = if cfg!(windows) {
        format!("echo test > \"{}\"", global_path.display())
    } else {
        format!("echo test > {}", global_path.display())
    };

    let res = guard.execute(&input(&cmd, temp_dir.clone()), sandbox.as_ref());

    if let Ok(ExecuteOutcome::Executed { output, .. }) = res {
        // If it "executed", check if it actually failed at OS level
        let stderr = output.stderr.to_lowercase();
        let access_denied = stderr.contains("denied") || stderr.contains("permission");
        assert!(
            access_denied || output.exit_code != 0,
            "Write to global path should be restricted. Output: {:?}",
            output
        );
    }

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_parity_filesystem_read_global() {
    let sandbox = get_active_sandbox();
    let caps = sandbox.capabilities();

    if !caps.filesystem_read_global {
        // Test that read is BLOCKED if capability is false
        let guard = Guard::from_yaml("version: 1\ndefault_mode: read_only").unwrap();
        let target = if cfg!(windows) {
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        } else {
            "/etc/hosts"
        };
        let cmd = if cfg!(windows) {
            format!("type {}", target)
        } else {
            format!("cat {}", target)
        };

        let res = guard.execute(
            &input(&cmd, std::env::current_dir().unwrap()),
            sandbox.as_ref(),
        );
        if let Ok(ExecuteOutcome::Executed { output, .. }) = res {
            assert!(
                output.exit_code != 0 || output.stdout.is_empty(),
                "Global read should be restricted"
            );
        }
    }
}

#[test]
fn test_parity_network_outbound() {
    let sandbox = get_active_sandbox();
    if !sandbox.is_available() {
        return;
    }
    let caps = sandbox.capabilities();

    if caps.network_outbound_any {
        return; // Current sandbox allows network
    }

    let guard = Guard::from_yaml("version: 1\ndefault_mode: full_access").unwrap();
    // Try a simple ping or curl
    let cmd = if cfg!(windows) {
        "ping -n 1 8.8.8.8"
    } else {
        "ping -c 1 8.8.8.8"
    };

    let res = guard.execute(
        &input(cmd, std::env::current_dir().unwrap()),
        sandbox.as_ref(),
    );
    if let Ok(ExecuteOutcome::Executed { output, .. }) = res {
        assert!(
            output.exit_code != 0,
            "Network outbound should be blocked. Output: {:?}",
            output
        );
    }
}

#[test]
fn test_parity_child_process_spawn() {
    let sandbox = get_active_sandbox();
    let caps = sandbox.capabilities();

    if !caps.child_process_spawn {
        return;
    }

    let guard = Guard::from_yaml("version: 1\ndefault_mode: read_only").unwrap();
    let cmd = if cfg!(windows) {
        "cmd /C \"echo 1\""
    } else {
        "sh -c \"echo 1\""
    };

    let res = guard.execute(
        &input(cmd, std::env::current_dir().unwrap()),
        sandbox.as_ref(),
    );
    assert!(res.is_ok());
    if let ExecuteOutcome::Executed { output, .. } = res.unwrap() {
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.contains('1'));
    }
}
