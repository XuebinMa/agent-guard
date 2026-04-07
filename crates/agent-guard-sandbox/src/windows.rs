use std::process::Command;
use crate::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult};

/// Windows sandbox implementation using Job Objects.
///
/// **Experimental Prototype**: Focuses on process tree management and resource
/// restriction. Fail-closed: if the environment setup fails, execution is blocked.
pub struct JobObjectSandbox;

impl Sandbox for JobObjectSandbox {
    fn name(&self) -> &'static str {
        "JobObject"
    }

    fn sandbox_type(&self) -> &'static str {
        "windows-job-object"
    }

    fn capabilities(&self) -> crate::SandboxCapabilities {
        crate::SandboxCapabilities {
            syscall_filtering: false,
            filesystem_isolation: false,
            network_blocking: false,
            resource_limits: true,
            process_tree_cleanup: true,
        }
    }

    #[cfg(not(windows))]
    fn execute(&self, _command: &str, _context: &SandboxContext) -> SandboxResult {
        Err(SandboxError::NotAvailable("JobObjectSandbox requires Windows.".to_string()))
    }

    #[cfg(windows)]
    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::*;
        use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;

        // 1. Create Job Object
        // Safety: Creating a private job object for the command.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job == 0 {
            return Err(SandboxError::ExecutionFailed("Windows Sandbox: Fail-closed - Failed to create Job Object".to_string()));
        }

        // RAII handle to ensure cleanup
        struct JobHandle(HANDLE);
        impl Drop for JobHandle {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let job_handle = JobHandle(job);

        // 2. Configure Limits: Kill all processes in job on handle close
        unsafe {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            
            let res = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if res == 0 {
                return Err(SandboxError::ExecutionFailed("Windows Sandbox: Fail-closed - Failed to configure Job Object".to_string()));
            }
        }

        // 3. Spawn process with breakaway flag
        let mut child = Command::new("cmd")
            .arg("/C")
            .arg(command)
            .current_dir(&context.working_directory)
            .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(format!("Windows Sandbox: spawn failed: {e}")))?;

        // 4. Assign to Job Object immediately
        unsafe {
            let res = AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE);
            if res == 0 {
                let _ = child.kill();
                return Err(SandboxError::ExecutionFailed("Windows Sandbox: Fail-closed - Failed to assign process to job".to_string()));
            }
        }

        // 5. Wait for output
        let output = child.wait_with_output()
            .map_err(|e| SandboxError::ExecutionFailed(format!("Windows Sandbox: wait failed: {e}")))?;

        Ok(SandboxOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    fn is_available(&self) -> bool {
        cfg!(windows)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::SandboxContext;
    use agent_guard_core::PolicyMode;
    use std::path::PathBuf;

    #[test]
    fn test_windows_job_object_lifecycle() {
        let sandbox = JobObjectSandbox;
        let ctx = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("."),
            timeout_ms: None,
        };
        let res = sandbox.execute("echo test", &ctx);
        assert!(res.is_ok(), "Windows execution should succeed within Job Object");
        let output = res.unwrap();
        assert!(output.stdout.contains("test"));
    }

    #[test]
    fn test_windows_fail_closed_logic() {
        // This is hard to test without mocking Win32, but we can verify 
        // that invalid commands or environments return proper errors.
        let sandbox = JobObjectSandbox;
        let ctx = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("NON_EXISTENT_DIR_12345"),
            timeout_ms: None,
        };
        let res = sandbox.execute("echo fail", &ctx);
        assert!(res.is_err(), "Execution in non-existent directory should fail-closed");
    }
}
