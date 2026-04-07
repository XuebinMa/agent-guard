use std::process::Command;
use crate::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult};

/// Windows sandbox implementation using Job Objects and Restricted Tokens.
///
/// **Experimental Prototype**: Focuses on resource restriction and process
/// lifetime management via Job Objects. Filesystem protection is currently 
/// best-effort via Low Integrity Level tokens (planned).
pub struct JobObjectSandbox;

impl Sandbox for JobObjectSandbox {
    fn name(&self) -> &'static str {
        "windows_job_object"
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
        // Mock execution for cross-platform documentation/testing
        Err(SandboxError::ExecutionFailed(
            "JobObjectSandbox is only functional on Windows.".to_string(),
        ))
    }

    #[cfg(windows)]
    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::*;
        use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;

        // 1. Create Job Object
        // Safety: Creating a private job object with default security attributes.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job == 0 {
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to create Job Object (fail-closed)".to_string(),
            ));
        }

        struct JobHandle(HANDLE);
        impl Drop for JobHandle {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let job_handle = JobHandle(job);

        // 2. Configure Limits: Kill child and all its descendants when the job handle is closed
        unsafe {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = 10; // Simple sanity limit

            let res = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );

            if res == 0 {
                return Err(SandboxError::ExecutionFailed(
                    "Windows Sandbox: Failed to configure Job Object limits".to_string(),
                ));
            }
        }

        // 3. Spawn process
        // We use CREATE_BREAKAWAY_FROM_JOB to ensure it doesn't try to inherit the parent's job
        // if the parent happens to be in one.
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
        // Safety: child.as_raw_handle() returns the process handle.
        unsafe {
            let res = AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE);
            if res == 0 {
                let _ = child.kill();
                return Err(SandboxError::ExecutionFailed(
                    "Windows Sandbox: Failed to assign process to Job Object".to_string(),
                ));
            }
        }

        // 5. Wait for output
        let output = child
            .wait_with_output()
            .map_err(|e| SandboxError::ExecutionFailed(format!("Windows Sandbox: wait failed: {e}")))?;

        // JobHandle drop will automatically kill any remaining processes in the job (due to LIMIT_KILL_ON_JOB_CLOSE)

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
