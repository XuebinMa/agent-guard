//! Windows Job Object integration tests.
//!
//! Run with:
//!   cargo test -p agent-guard-sandbox --features windows-sandbox --test windows_job_integration

#[cfg(all(target_os = "windows", feature = "windows-sandbox"))]
mod windows_job_tests {
    use std::path::PathBuf;

    use agent_guard_core::PolicyMode;
    use agent_guard_sandbox::{JobObjectSandbox, Sandbox, SandboxContext, SandboxOutput};

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

    #[test]
    fn w0_job_object_is_available_on_runner() {
        let sandbox = JobObjectSandbox;
        assert!(sandbox.is_available());
    }

    #[test]
    fn w1_command_executes_inside_job_object() {
        let sandbox = JobObjectSandbox;

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
