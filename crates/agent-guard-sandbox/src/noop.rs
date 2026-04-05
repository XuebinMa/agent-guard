use super::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult};

/// No-op sandbox — passthrough with no OS-level isolation.
///
/// Suitable for local development, testing, and platforms where OS-level
/// sandboxing is not yet implemented (macOS Phase 3, Windows Phase 4).
/// On Linux, prefer `SeccompSandbox` for production use.
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let start = Instant::now();
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(&context.working_directory)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

        if let Some(timeout_ms) = context.timeout_ms {
            let limit = Duration::from_millis(timeout_ms);
            loop {
                if start.elapsed() >= limit {
                    let _ = child.kill();
                    return Err(SandboxError::Timeout { ms: timeout_ms });
                }
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(e) => return Err(SandboxError::ExecutionFailed(e.to_string())),
                }
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

        Ok(SandboxOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl NoopSandbox {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopSandbox {
    fn default() -> Self {
        Self::new()
    }
}
