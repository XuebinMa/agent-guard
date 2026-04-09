use std::process::Command;
use crate::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult, SandboxCapabilities};

/// macOS Seatbelt sandbox using sandbox-exec.
pub struct SeatbeltSandbox;

impl Sandbox for SeatbeltSandbox {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn sandbox_type(&self) -> &'static str {
        "macos-seatbelt"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: true, // Seatbelt prototype currently allows global read
            filesystem_write_workspace: true,
            filesystem_write_global: false,
            network_outbound_any: false,
            network_outbound_internet: false,
            network_outbound_local: false,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    fn is_available(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        #[cfg(target_os = "macos")]
        {
            let resolved_dir = context.working_directory.canonicalize()
                .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to resolve workspace path: {}", e)))?;

            let profile = format!(
                r#"(version 1)
(deny default)
(allow file-read* (subpath "/"))
(allow file-write* (subpath "{}"))
(allow process-fork)
(allow process-exec)
(deny network*)"#,
                resolved_dir.display()
            );

            // CWE-78: Command Injection Mitigation.
            let escaped_command = command.replace("'", "'\\''");
            let mut child = Command::new("sandbox-exec")
                .arg("-p")
                .arg(profile)
                .arg("sh")
                .arg("-c")
                .arg(format!("'{}'", escaped_command))
                .current_dir(&context.working_directory)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to spawn sandbox-exec: {}", e)))?;

            // Handle timeout if specified
            if let Some(timeout_ms) = context.timeout_ms {
                use std::time::Duration;
                use std::thread;
                use std::sync::mpsc;

                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(timeout_ms));
                    let _ = tx.send(());
                });

                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let output = child.wait_with_output().map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;
                            return Ok(SandboxOutput {
                                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                                exit_code: status.code().unwrap_or(-1),
                            });
                        }
                        Ok(None) => {
                            if rx.try_recv().is_ok() {
                                let _ = child.kill();
                                let _ = child.wait(); // Prevent zombie
                                return Err(SandboxError::Timeout { ms: timeout_ms });
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => return Err(SandboxError::ExecutionFailed(e.to_string())),
                    }
                }
            }

            let output = child.wait_with_output()
                .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to wait for sandboxed process: {}", e)))?;

            Ok(SandboxOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                exit_code: output.status.code().unwrap_or(-1),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(SandboxError::NotAvailable("Seatbelt is only available on macOS".to_string()))
        }
    }
}
