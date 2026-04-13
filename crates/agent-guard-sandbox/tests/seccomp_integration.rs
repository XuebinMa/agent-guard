//! Linux seccomp integration tests.
//!
//! These tests require:
//!   - Linux kernel with seccomp support (3.5+)
//!   - `libseccomp` C library installed
//!   - Feature flag: `cargo test --features agent-guard-sandbox/seccomp`
//!
//! The tests are gated on `target_os = "linux"` AND the `seccomp` feature flag.
//! On macOS / Windows they are compiled out entirely.
//!
//! Run with:
//!   cargo test -p agent-guard-sandbox --features seccomp -- seccomp_integration

#[cfg(all(target_os = "linux", feature = "seccomp"))]
mod seccomp_tests {
    use std::path::PathBuf;

    use agent_guard_core::PolicyMode;
    use agent_guard_sandbox::{
        linux::SeccompSandbox, Sandbox, SandboxContext, SandboxError, SandboxOutput,
    };

    fn tmp_dir() -> PathBuf {
        std::env::temp_dir()
    }

    fn ctx(mode: PolicyMode) -> SandboxContext {
        SandboxContext {
            mode,
            working_directory: tmp_dir(),
            timeout_ms: Some(5_000),
        }
    }

    #[test]
    fn c0_capabilities_are_sandbox_wide_metadata() {
        let caps = SeccompSandbox::strict().capabilities();

        assert!(caps.filesystem_write_workspace);
        assert!(caps.filesystem_write_global);
        assert!(caps.network_outbound_any);
    }

    // ── C1: ReadOnly — allow read-only commands ────────────────────────────

    #[test]
    fn c1_read_only_allows_echo() {
        let sandbox = SeccompSandbox::strict();
        let result = sandbox.execute("echo hello", &ctx(PolicyMode::ReadOnly));
        match result {
            Ok(SandboxOutput {
                stdout, exit_code, ..
            }) => {
                assert_eq!(exit_code, 0, "echo should exit 0");
                assert_eq!(stdout.trim(), "hello", "stdout = {stdout:?}");
            }
            Err(e) => panic!("expected Ok, got Err: {e}"),
        }
    }

    #[test]
    fn c1_read_only_allows_stat() {
        let sandbox = SeccompSandbox::strict();
        let result = sandbox.execute("stat /etc/hostname", &ctx(PolicyMode::ReadOnly));
        match result {
            Ok(SandboxOutput { exit_code, .. }) => {
                assert_eq!(exit_code, 0, "stat /etc/hostname should succeed");
            }
            Err(e) => panic!("expected Ok, got Err: {e}"),
        }
    }

    // ── C2: ReadOnly — runtime enforcement is stricter than static metadata ──

    #[test]
    fn c2_read_only_blocks_file_write() {
        let sandbox = SeccompSandbox::strict();
        let target = tmp_dir().join("seccomp_test_write.txt");
        // Use `tee` to write a file — tee calls `open(O_WRONLY)` / `creat` which
        // should be blocked by the seccomp filter in read_only mode.
        let cmd = format!("echo data | tee {}", target.display());
        let result = sandbox.execute(&cmd, &ctx(PolicyMode::ReadOnly));

        match result {
            Err(SandboxError::KilledByFilter { .. }) => {
                // Expected on kernels that terminate the process for a blocked syscall.
            }
            Ok(out) => {
                assert_ne!(
                    out.exit_code, 0,
                    "write should not succeed in read_only mode; got exit 0"
                );
                assert!(
                    !target.exists(),
                    "read_only write should not create the target file"
                );
            }
            Err(e) => panic!("unexpected error: {e}"),
        }

        let _ = std::fs::remove_file(&target);
    }

    // ── C3: WorkspaceWrite — allow writes inside working_directory ─────────

    #[test]
    fn c3_workspace_write_allows_write_in_dir() {
        let sandbox = SeccompSandbox::strict();
        let target = tmp_dir().join("seccomp_test_ws_write.txt");
        let cmd = format!("echo workspace > {}", target.display());
        let result = sandbox.execute(&cmd, &ctx(PolicyMode::WorkspaceWrite));
        match result {
            Ok(SandboxOutput { exit_code, .. }) => {
                assert_eq!(exit_code, 0, "write in workspace should succeed");
                // Verify the file was actually created.
                assert!(target.exists(), "file should exist after write");
            }
            Err(e) => panic!("expected Ok, got Err: {e}"),
        }
        let _ = std::fs::remove_file(&target);
    }

    // ── C4: FullAccess — no filter, all syscalls allowed ──────────────────

    #[test]
    fn c4_full_access_no_filter() {
        let sandbox = SeccompSandbox::strict();
        // FullAccess should execute without any seccomp restriction.
        let result = sandbox.execute("ls /tmp", &ctx(PolicyMode::FullAccess));
        match result {
            Ok(SandboxOutput { exit_code, .. }) => {
                assert_eq!(exit_code, 0);
            }
            Err(e) => panic!("expected Ok for FullAccess, got Err: {e}"),
        }
    }

    // ── C5: Strict mode — filter setup failure is hard error ─────────────

    #[test]
    fn c5_strict_read_only_executes_with_native_filter() {
        let sandbox = SeccompSandbox::strict();
        let result = sandbox.execute("echo strict", &ctx(PolicyMode::ReadOnly));
        match result {
            Ok(SandboxOutput {
                stdout, exit_code, ..
            }) => {
                assert_eq!(
                    exit_code, 0,
                    "strict mode should allow safe read-only commands"
                );
                assert_eq!(stdout.trim(), "strict");
            }
            Err(e) => panic!("strict mode should use native seccomp, got Err: {e}"),
        }
    }

    // ── C6: Timeout ──────────────────────────────────────────────────────

    #[test]
    fn c6_timeout_kills_long_running_command() {
        let sandbox = SeccompSandbox::strict();
        let ctx = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: tmp_dir(),
            timeout_ms: Some(200),
        };
        let result = sandbox.execute("sleep 10", &ctx);
        match result {
            Err(SandboxError::Timeout { ms }) => {
                assert_eq!(ms, 200);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }
}
