//! macOS Seatbelt integration tests.
//!
//! Run with:
//!   cargo test -p agent-guard-sandbox --features macos-sandbox --test macos_integration

#[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
mod macos_tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

    use agent_guard_core::PolicyMode;
    use agent_guard_sandbox::{
        Sandbox, SandboxContext, SandboxError, SandboxOutput, SeatbeltSandbox,
    };

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join("agent_guard_macos_integration");
        let _ = std::fs::create_dir_all(&root);
        root
    }

    fn workspace_dir() -> PathBuf {
        let dir = temp_root().join("workspace");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn outside_dir() -> PathBuf {
        let dir = temp_root().join("outside");
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

    fn seatbelt_available(sandbox: &SeatbeltSandbox) -> bool {
        if sandbox.is_available() {
            return true;
        }

        eprintln!("skipping Seatbelt enforcement assertions: sandbox-exec is not functional on this macOS host");
        false
    }

    #[test]
    fn m0_seatbelt_runtime_contract_is_honest() {
        let sandbox = SeatbeltSandbox;
        let caps = sandbox.capabilities();

        if sandbox.is_available() {
            assert!(caps.filesystem_read_workspace);
            assert!(caps.filesystem_read_global);
            assert!(caps.filesystem_write_workspace);
            assert!(!caps.filesystem_write_global);
            assert!(!caps.network_outbound_any);
            return;
        }

        assert!(!caps.filesystem_read_workspace);
        assert!(!caps.filesystem_read_global);
        assert!(!caps.filesystem_write_workspace);
        assert!(!caps.filesystem_write_global);
        assert!(!caps.network_outbound_any);

        let err = sandbox
            .execute("true", &ctx())
            .expect_err("unavailable Seatbelt runtime must fail closed");
        assert!(matches!(err, SandboxError::NotAvailable(_)));
    }

    #[test]
    fn m1_workspace_write_is_allowed() {
        let sandbox = SeatbeltSandbox;
        if !seatbelt_available(&sandbox) {
            return;
        }

        let target = workspace_dir().join("seatbelt_workspace_write.txt");
        let cmd = format!("echo seatbelt > {}", target.display());

        match sandbox.execute(&cmd, &ctx()) {
            Ok(SandboxOutput { exit_code, .. }) => {
                assert_eq!(exit_code, 0, "workspace write should succeed");
                assert!(target.exists(), "workspace file should exist");
            }
            Err(err) => panic!("expected successful workspace write, got {err}"),
        }
    }

    #[test]
    fn m2_global_write_is_blocked() {
        let sandbox = SeatbeltSandbox;
        if !seatbelt_available(&sandbox) {
            return;
        }

        let target = outside_dir().join("seatbelt_global_write.txt");
        let cmd = format!("echo denied > {}", target.display());

        match sandbox.execute(&cmd, &ctx()) {
            Ok(output) => {
                assert_ne!(
                    output.exit_code, 0,
                    "global write should not succeed under Seatbelt: {output:?}"
                );
                assert!(!target.exists(), "global write should not create the file");
            }
            Err(err) => panic!("expected command execution result, got {err}"),
        }
    }

    #[test]
    fn m3_network_is_blocked() {
        let sandbox = SeatbeltSandbox;
        if !seatbelt_available(&sandbox) {
            return;
        }

        let (port, server) = start_local_echo_server();

        match sandbox.execute(&python_local_socket_cmd(port), &ctx()) {
            Ok(output) => {
                assert_ne!(
                    output.exit_code, 0,
                    "network connect should not succeed under Seatbelt: {output:?}"
                );
            }
            Err(err) => panic!("expected command execution result, got {err}"),
        }

        assert!(
            !server.join().expect("join server thread"),
            "blocked network should not reach the local echo server"
        );
    }
}
