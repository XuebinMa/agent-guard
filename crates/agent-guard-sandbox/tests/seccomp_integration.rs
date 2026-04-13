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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

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

    fn start_local_echo_server() -> (u16, thread::JoinHandle<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test listener");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let port = listener.local_addr().expect("listener addr").port();

        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _addr)) => {
                        let mut buf = [0_u8; 16];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(b"pong\n");
                        return true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => return false,
                }
            }

            false
        });

        (port, handle)
    }

    fn python_local_socket_cmd(port: u16) -> String {
        format!(
            "python3 -c 'import socket; s = socket.create_connection((\"127.0.0.1\", {port}), timeout=2); s.sendall(b\"ping\"); print(s.recv(16).decode().strip())'"
        )
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

    #[test]
    fn c2_read_only_blocks_network_connect() {
        let sandbox = SeccompSandbox::strict();
        let (port, server) = start_local_echo_server();
        let result = sandbox.execute(&python_local_socket_cmd(port), &ctx(PolicyMode::ReadOnly));

        match result {
            Err(SandboxError::KilledByFilter { .. }) => {}
            Ok(out) => {
                assert_ne!(
                    out.exit_code, 0,
                    "network connect should not succeed in read_only mode; output: {out:?}"
                );
            }
            Err(e) => panic!("unexpected error: {e}"),
        }

        assert!(
            !server.join().expect("join server thread"),
            "read_only mode should not reach the local echo server"
        );
    }

    // ── C3: WorkspaceWrite — write allowed, networking still blocked ──────

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

    #[test]
    fn c3_workspace_write_blocks_network_connect() {
        let sandbox = SeccompSandbox::strict();
        let (port, server) = start_local_echo_server();
        let result = sandbox.execute(
            &python_local_socket_cmd(port),
            &ctx(PolicyMode::WorkspaceWrite),
        );

        match result {
            Err(SandboxError::KilledByFilter { .. }) => {}
            Ok(out) => {
                assert_ne!(
                    out.exit_code, 0,
                    "network connect should not succeed in workspace_write mode; output: {out:?}"
                );
            }
            Err(e) => panic!("unexpected error: {e}"),
        }

        assert!(
            !server.join().expect("join server thread"),
            "workspace_write mode should not reach the local echo server"
        );
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

    #[test]
    fn c4_full_access_allows_local_network_connect() {
        let sandbox = SeccompSandbox::strict();
        let (port, server) = start_local_echo_server();
        let result = sandbox.execute(&python_local_socket_cmd(port), &ctx(PolicyMode::FullAccess));

        match result {
            Ok(SandboxOutput {
                stdout, exit_code, ..
            }) => {
                assert_eq!(exit_code, 0, "full_access local network should succeed");
                assert_eq!(stdout.trim(), "pong");
            }
            Err(e) => panic!("expected Ok for FullAccess local network, got Err: {e}"),
        }

        assert!(
            server.join().expect("join server thread"),
            "full_access mode should reach the local echo server"
        );
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
