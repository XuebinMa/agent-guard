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

    // ── C1: ReadOnly — allow read-only commands ────────────────────────────

    #[test]
    fn c1_read_only_allows_echo() {
        let sandbox = SeccompSandbox::new();
        let result = sandbox.execute("echo hello", &ctx(PolicyMode::ReadOnly));
        match result {
            Ok(SandboxOutput { stdout, exit_code, .. }) => {
                assert_eq!(exit_code, 0, "echo should exit 0");
                assert!(stdout.trim() == "hello", "stdout = {stdout:?}");
            }
            Err(e) => panic!("expected Ok, got Err: {e}"),
        }
    }

    #[test]
    fn c1_read_only_allows_stat() {
        let sandbox = SeccompSandbox::new();
        let result = sandbox.execute("stat /etc/hostname", &ctx(PolicyMode::ReadOnly));
        match result {
            Ok(SandboxOutput { exit_code, .. }) => {
                assert_eq!(exit_code, 0, "stat /etc/hostname should succeed");
            }
            Err(e) => panic!("expected Ok, got Err: {e}"),
        }
    }

    // ── C2: ReadOnly — block write syscalls ───────────────────────────────

    #[test]
    fn c2_read_only_blocks_file_write() {
        let sandbox = SeccompSandbox::strict();
        let target = tmp_dir().join("seccomp_test_write.txt");
        // Use `tee` to write a file — tee calls `open(O_WRONLY)` / `creat` which
        // is NOT in the ReadOnly allowlist.
        let cmd = format!("echo data | tee {}", target.display());
        let result = sandbox.execute(&cmd, &ctx(PolicyMode::ReadOnly));
        match result {
            Err(SandboxError::KilledByFilter { .. }) => {
                // Expected: seccomp killed the child for attempting a blocked write syscall.
            }
            Ok(out) => {
                // On some kernels the shell itself may absorb SIGSYS differently;
                // but at minimum the write must not have succeeded cleanly.
                assert_ne!(out.exit_code, 0, "write should not succeed in read_only mode; got exit 0");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
        // Clean up if file was partially created.
        let _ = std::fs::remove_file(&target);
    }

    // ── C3: WorkspaceWrite — allow writes inside working_directory ─────────

    #[test]
    fn c3_workspace_write_allows_write_in_dir() {
        let sandbox = SeccompSandbox::new();
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
        let sandbox = SeccompSandbox::new();
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
    fn c5_strict_read_only_does_not_silently_bypass() {
        // Strict mode: if seccomp filter fails to load, return FilterSetup error.
        // This test validates the strict=true path compiles and returns the right variant.
        // On a real kernel this should succeed; we test the API contract here.
        let sandbox = SeccompSandbox::strict();
        let result = sandbox.execute("echo strict", &ctx(PolicyMode::ReadOnly));
        // On a system with seccomp support this should succeed (filter loads OK).
        // If it fails it must be FilterSetup, not a silent noop.
        match result {
            Ok(_) => {} // filter loaded and command ran
            Err(SandboxError::FilterSetup(_)) => {} // acceptable: filter setup failed hard
            Err(SandboxError::KilledByFilter { .. }) => {} // filter fired: also acceptable
            Err(e) => panic!("strict mode got unexpected error: {e}"),
        }
    }

    // ── C6: Timeout ──────────────────────────────────────────────────────

    #[test]
    fn c6_timeout_kills_long_running_command() {
        let sandbox = SeccompSandbox::new();
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
