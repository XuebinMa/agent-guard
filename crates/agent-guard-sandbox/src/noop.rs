use super::{
    Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxOutput, SandboxResult,
};

/// No-op sandbox — passthrough with no OS-level isolation.
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn sandbox_type(&self) -> &'static str {
        "none"
    }

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

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        use std::process::Command;
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
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

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

    fn is_available(&self) -> bool {
        true
    }
}
