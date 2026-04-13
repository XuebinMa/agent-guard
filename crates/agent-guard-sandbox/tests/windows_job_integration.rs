//! Windows Job Object integration tests.
//!
//! Run with:
//!   cargo test -p agent-guard-sandbox --features windows-sandbox --test windows_job_integration

#[cfg(all(target_os = "windows", feature = "windows-sandbox"))]
mod windows_job_tests {
    use std::path::PathBuf;

    use agent_guard_core::PolicyMode;
    use agent_guard_sandbox::{
        JobObjectSandbox, Sandbox, SandboxContext, SandboxError, SandboxOutput,
    };

    fn workspace_dir() -> PathBuf {
        let dir = std::env::temp_dir().join("agent_guard_windows_job_integration");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn ctx() -> SandboxContext {
        SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: workspace_dir(),
            timeout_ms: Some(5_000),
        }
    }

    fn job_object_available(sandbox: &JobObjectSandbox) -> bool {
        if sandbox.is_available() {
            return true;
        }

        eprintln!(
            "skipping Job Object enforcement assertions: low-integrity process creation is not functional on this Windows host"
        );
        false
    }

    #[test]
    fn w0_job_object_runtime_contract_is_honest() {
        let sandbox = JobObjectSandbox;
        let caps = sandbox.capabilities();

        if sandbox.is_available() {
            assert!(caps.filesystem_read_workspace);
            assert!(caps.filesystem_read_global);
            assert!(caps.filesystem_write_workspace);
            assert!(!caps.filesystem_write_global);
            assert!(caps.network_outbound_any);
            return;
        }

        assert!(!caps.filesystem_read_workspace);
        assert!(!caps.filesystem_read_global);
        assert!(!caps.filesystem_write_workspace);
        assert!(!caps.filesystem_write_global);
        assert!(!caps.network_outbound_any);

        let err = sandbox
            .execute("echo unavailable", &ctx())
            .expect_err("unavailable JobObject runtime must fail closed");
        assert!(matches!(err, SandboxError::NotAvailable(_)));
    }

    #[test]
    fn w1_command_executes_inside_job_object() {
        let sandbox = JobObjectSandbox;
        if !job_object_available(&sandbox) {
            return;
        }

        match sandbox.execute("echo windows_job_object_ok", &ctx()) {
            Ok(SandboxOutput {
                stdout, exit_code, ..
            }) => {
                assert_eq!(exit_code, 0);
                assert!(stdout.contains("windows_job_object_ok"));
            }
            Err(err) => panic!("expected successful job object execution, got {err}"),
        }
    }

    #[test]
    fn w2_working_directory_is_applied() {
        let sandbox = JobObjectSandbox;
        if !job_object_available(&sandbox) {
            return;
        }
        let expected = workspace_dir();

        match sandbox.execute("cd", &ctx()) {
            Ok(SandboxOutput {
                stdout, exit_code, ..
            }) => {
                assert_eq!(exit_code, 0, "working-directory probe should succeed");
                assert!(
                    stdout.to_lowercase().contains(&expected.display().to_string().to_lowercase()),
                    "current directory should match sandbox context. stdout={stdout:?}, expected={expected:?}"
                );
            }
            Err(err) => panic!("expected successful working-directory probe, got {err}"),
        }
    }

    #[test]
    fn w3_global_write_is_blocked_by_low_integrity() {
        let sandbox = JobObjectSandbox;
        if !job_object_available(&sandbox) {
            return;
        }
        let target = PathBuf::from(r"C:\Windows\agent_guard_job_object_integration.txt");
        let cmd = format!("echo denied > {}", target.display());

        match sandbox.execute(&cmd, &ctx()) {
            Ok(output) => {
                let stderr = output.stderr.to_lowercase();
                assert!(
                    stderr.contains("access is denied") || output.exit_code != 0,
                    "global system write should be blocked by Low-IL: {output:?}"
                );
            }
            Err(err) => panic!("expected command execution result, got {err}"),
        }
    }
}
