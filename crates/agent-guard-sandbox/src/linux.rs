//! Linux seccomp-bpf sandbox.

use crate::{
    Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxOutput, SandboxResult,
};
use std::process::Command;

/// Linux seccomp-bpf sandbox.
///
/// **PROTOTYPE**: Current implementation is a wrapper around `sh -c`.
/// Native Seccomp-BPF integration is planned for v0.3.0.
pub struct SeccompSandbox {
    strict: bool,
}

impl SeccompSandbox {
    pub fn new() -> Self {
        Self { strict: true }
    }

    pub fn strict() -> Self {
        Self { strict: true }
    }
}

impl Default for SeccompSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for SeccompSandbox {
    fn name(&self) -> &'static str {
        "seccomp"
    }

    fn sandbox_type(&self) -> &'static str {
        "linux-seccomp"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        // PROTOTYPE: Current implementation is plain `sh -c` without seccomp filters.
        // Capabilities reflect actual enforcement, not planned Seccomp-BPF behavior.
        SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: true,
            filesystem_write_workspace: true,
            filesystem_write_global: true, // No kernel-level write blocking yet
            network_outbound_any: true,    // No syscall filtering yet
            network_outbound_internet: true,
            network_outbound_local: true,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        execute_with_seccomp(command, context, self.strict)
    }

    fn is_available(&self) -> bool {
        cfg!(target_os = "linux")
    }
}

fn execute_with_seccomp(command: &str, context: &SandboxContext, _strict: bool) -> SandboxResult {
    #[cfg(target_os = "linux")]
    {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(&context.working_directory)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                SandboxError::ExecutionFailed(format!("Failed to spawn process: {}", e))
            })?;

        // Handle timeout if specified
        if let Some(timeout_ms) = context.timeout_ms {
            let (tx, rx) = mpsc::channel();

            thread::spawn(move || {
                thread::sleep(Duration::from_millis(timeout_ms));
                let _ = tx.send(());
            });

            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let output = child
                            .wait_with_output()
                            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;
                        return Ok(SandboxOutput {
                            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                            exit_code: status.code().unwrap_or(-1),
                        });
                    }
                    Ok(None) => {
                        if rx.try_recv().is_ok() {
                            let _ = child.kill();
                            let _ = child.wait(); // CWE-117: Prevent zombie process
                            return Err(SandboxError::Timeout { ms: timeout_ms });
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => return Err(SandboxError::ExecutionFailed(e.to_string())),
                }
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

        Ok(SandboxOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SandboxError::NotAvailable(
            "Seccomp is only available on Linux".to_string(),
        ))
    }
}
