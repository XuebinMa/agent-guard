//! Linux Landlock filesystem-boundary integration tests.
//!
//! These tests require a kernel with Landlock ABI v3 or newer and run only
//! when the crate is built on Linux with the `landlock` feature:
//!
//! ```text
//! cargo test -p agent-guard-sandbox --features landlock --test landlock_integration -- --nocapture
//! ```

#[cfg(all(target_os = "linux", feature = "landlock"))]
mod landlock_tests {
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, RawFd};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use agent_guard_core::PolicyMode;
    use agent_guard_sandbox::{LandlockSandbox, Sandbox, SandboxContext, SandboxOutput};

    struct Fixture {
        _root: tempfile::TempDir,
        workspace: PathBuf,
        outside: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            let workspace = root.path().join("workspace");
            let outside = root.path().join("outside");
            std::fs::create_dir_all(&workspace).expect("workspace");
            std::fs::create_dir_all(&outside).expect("outside");
            Self {
                _root: root,
                workspace,
                outside,
            }
        }

        fn context(&self, mode: PolicyMode) -> SandboxContext {
            SandboxContext {
                mode,
                working_directory: self.workspace.clone(),
                timeout_ms: Some(5_000),
            }
        }
    }

    struct InheritedFd(RawFd);

    impl Drop for InheritedFd {
        fn drop(&mut self) {
            // SAFETY: this type owns the descriptor returned by F_DUPFD and
            // closes it exactly once here.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    fn available_sandbox() -> LandlockSandbox {
        let sandbox = LandlockSandbox;
        assert!(
            sandbox.is_available(),
            "Landlock integration tests require an enabled ABI v3+ host"
        );
        sandbox
    }

    fn require_python3() {
        let status = Command::new("python3")
            .arg("--version")
            .status()
            .expect("python3 is required for exact syscall probes");
        assert!(status.success(), "python3 must run for syscall probes");
    }

    fn python_path(path: &Path) -> String {
        serde_json::to_string(
            path.to_str()
                .expect("temporary integration-test paths are UTF-8"),
        )
        .expect("path serializes")
    }

    fn assert_denied(result: Result<SandboxOutput, agent_guard_sandbox::SandboxError>) {
        match result {
            Ok(output) => assert_ne!(
                output.exit_code, 0,
                "filesystem mutation unexpectedly succeeded: {output:?}"
            ),
            Err(error) => {
                panic!("Landlock setup/execution failed instead of denying in-child: {error}")
            }
        }
    }

    fn assert_unchanged(path: &Path, expected: &str) {
        assert_eq!(
            std::fs::read_to_string(path).expect("read probe file"),
            expected,
            "denied mutation changed {}",
            path.display()
        );
    }

    #[test]
    fn read_only_blocks_writes_inside_the_workspace() {
        require_python3();
        let sandbox = available_sandbox();
        let fixture = Fixture::new();
        let target = fixture.workspace.join("read-only.txt");
        std::fs::write(&target, "original").expect("seed target");
        let command = format!(
            "python3 -c 'import os; p={}; fd=os.open(p, os.O_WRONLY | os.O_TRUNC); os.write(fd, b\"changed\"); os.close(fd)'",
            python_path(&target)
        );

        assert_denied(sandbox.execute(&command, &fixture.context(PolicyMode::ReadOnly)));
        assert_unchanged(&target, "original");
    }

    #[test]
    fn workspace_write_allows_writes_inside_the_workspace() {
        require_python3();
        let sandbox = available_sandbox();
        let fixture = Fixture::new();
        let target = fixture.workspace.join("workspace-write.txt");
        let command = format!(
            "python3 -c 'import os; p={}; fd=os.open(p, os.O_WRONLY | os.O_CREAT, 0o600); os.write(fd, b\"written\"); os.close(fd)'",
            python_path(&target)
        );

        let output = sandbox
            .execute(&command, &fixture.context(PolicyMode::WorkspaceWrite))
            .expect("Landlock execution");
        assert_eq!(output.exit_code, 0, "workspace write failed: {output:?}");
        assert_unchanged(&target, "written");
    }

    #[test]
    fn workspace_write_blocks_truncate_outside_the_workspace() {
        require_python3();
        let sandbox = available_sandbox();
        let fixture = Fixture::new();
        let target = fixture.outside.join("truncate.txt");
        std::fs::write(&target, "original").expect("seed target");
        let command = format!(
            "python3 -c 'import os; os.truncate({}, 0)'",
            python_path(&target)
        );

        assert_denied(sandbox.execute(&command, &fixture.context(PolicyMode::WorkspaceWrite)));
        assert_unchanged(&target, "original");
    }

    #[test]
    fn workspace_write_blocks_ftruncate_on_an_inherited_outside_fd() {
        require_python3();
        let sandbox = available_sandbox();
        let fixture = Fixture::new();
        let target = fixture.outside.join("ftruncate.txt");
        std::fs::write(&target, "original").expect("seed target");
        let file = OpenOptions::new()
            .write(true)
            .open(&target)
            .expect("open target before entering Landlock domain");
        // F_DUPFD returns a descriptor without FD_CLOEXEC, so the shell and
        // Python probe inherit it across the sandbox's exec boundary.
        // SAFETY: `file` is open and `fcntl` does not outlive this scope.
        let inherited = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 200) };
        assert!(
            inherited >= 0,
            "duplicate inherited fd: {}",
            std::io::Error::last_os_error()
        );
        let inherited = InheritedFd(inherited);
        let command = format!("python3 -c 'import os; os.ftruncate({}, 0)'", inherited.0);

        assert_denied(sandbox.execute(&command, &fixture.context(PolicyMode::WorkspaceWrite)));
        assert_unchanged(&target, "original");
    }

    #[test]
    fn workspace_write_blocks_read_only_open_with_o_trunc_outside_workspace() {
        require_python3();
        let sandbox = available_sandbox();
        let fixture = Fixture::new();
        let target = fixture.outside.join("o-trunc.txt");
        std::fs::write(&target, "original").expect("seed target");
        // O_RDONLY avoids relying on the older WRITE_FILE right. This probe
        // specifically requires ABI v3's TRUNCATE right to stop the mutation.
        let command = format!(
            "python3 -c 'import os; p={}; fd=os.open(p, os.O_RDONLY | os.O_TRUNC); os.close(fd)'",
            python_path(&target)
        );

        assert_denied(sandbox.execute(&command, &fixture.context(PolicyMode::WorkspaceWrite)));
        assert_unchanged(&target, "original");
    }
}
