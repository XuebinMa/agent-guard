use crate::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult};

/// Windows sandbox implementation using Job Objects and Restricted Tokens.
///
/// **Strengthened Prototype (Phase 5)**: Enforces process tree isolation via
/// Job Objects and filesystem write protection via Low Integrity Level (Low-IL)
/// tokens. Fail-closed: if the environment setup fails, execution is blocked.
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
            filesystem_isolation: true, // Low-IL provides write isolation
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
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::*;

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
        let _job_guard = JobHandle(job);

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

        // 3. Create Low Integrity Token (M5.1)
        let token = create_low_integrity_token()?;
        let _token_guard = TokenHandle(token);

        // 4. Execute with Restricted Token (CRITICAL ENFORCEMENT)
        // This is the ACTIVE implementation using CreateProcessAsUserW.
        // It ENSURES the restricted token is applied to the child process.
        let output = spawn_low_integrity_process(command, &context.working_directory, token, job)?;

        Ok(SandboxOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }

    fn is_available(&self) -> bool {
        cfg!(windows)
    }
}

// RAII handle to ensure Win32 handles are closed.
struct SafeHandle(windows_sys::Win32::Foundation::HANDLE);
impl Drop for SafeHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

struct TokenHandle(windows_sys::Win32::Foundation::HANDLE);
impl Drop for TokenHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

struct WaitOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[cfg(windows)]
fn create_low_integrity_token() -> Result<windows_sys::Win32::Foundation::HANDLE, SandboxError> {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};

    unsafe {
        let mut process_token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &mut process_token) == 0 {
            return Err(SandboxError::ExecutionFailed("Windows Sandbox: Failed to open process token".to_string()));
        }
        let _pt_guard = SafeHandle(process_token);

        let mut low_token: HANDLE = 0;
        if DuplicateTokenEx(process_token, TOKEN_ALL_ACCESS, std::ptr::null(), SecurityImpersonation, TokenPrimary, &mut low_token) == 0 {
            return Err(SandboxError::ExecutionFailed("Windows Sandbox: Failed to duplicate token".to_string()));
        }
        
        let mut integrity_sid: *mut std::ffi::c_void = std::ptr::null_mut();
        // S-1-16-4096 (Low Mandatory Level)
        let mut low_integrity_sid_auth = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 16] };
        if AllocateAndInitializeSid(&low_integrity_sid_auth, 1, 0x1000, 0, 0, 0, 0, 0, 0, 0, &mut integrity_sid) == 0 {
            CloseHandle(low_token);
            return Err(SandboxError::ExecutionFailed("Windows Sandbox: Failed to allocate SID".to_string()));
        }

        let mut tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: integrity_sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };

        let res = SetTokenInformation(low_token, TokenIntegrityLevel, &tml as *const _ as *const _, std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32);
        FreeSid(integrity_sid);

        if res == 0 {
            CloseHandle(low_token);
            return Err(SandboxError::ExecutionFailed("Windows Sandbox: Failed to set token integrity level".to_string()));
        }

        Ok(low_token)
    }
}

#[cfg(windows)]
fn spawn_low_integrity_process(
    command: &str,
    working_dir: &std::path::Path,
    token: windows_sys::Win32::Foundation::HANDLE,
    job: windows_sys::Win32::Foundation::HANDLE,
) -> Result<WaitOutput, SandboxError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Threading::*;
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};

    unsafe {
        // Prepare command line
        let cmd_string = format!("cmd /C \"{}\"", command);
        let mut cmd_vec: Vec<u16> = std::ffi::OsStr::new(&cmd_string).encode_wide().chain(std::iter::once(0)).collect();
        let mut working_dir_vec: Vec<u16> = working_dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE as u16;

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // 1. Spawn process suspended to allow job assignment
        let success = CreateProcessAsUserW(
            token,
            std::ptr::null(),
            cmd_vec.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED,
            std::ptr::null(),
            working_dir_vec.as_ptr(),
            &si,
            &mut pi,
        );

        if success == 0 {
            let err = std::io::Error::last_os_error();
            return Err(SandboxError::ExecutionFailed(format!("Windows Sandbox: CreateProcessAsUserW failed: {err}")));
        }

        let _process_guard = SafeHandle(pi.hProcess);
        let _thread_guard = SafeHandle(pi.hThread);

        // 2. Assign to Job Object before resuming
        if AssignProcessToJobObject(job, pi.hProcess) == 0 {
            let _ = TerminateProcess(pi.hProcess, 1);
            return Err(SandboxError::ExecutionFailed("Windows Sandbox: Fail-closed - Failed to assign process to job".to_string()));
        }

        // 3. Resume process
        if ResumeThread(pi.hThread) == u32::MAX {
            let _ = TerminateProcess(pi.hProcess, 1);
            return Err(SandboxError::ExecutionFailed("Windows Sandbox: Failed to resume low-IL process".to_string()));
        }

        // 4. Wait for completion
        WaitForSingleObject(pi.hProcess, INFINITE);

        let mut exit_code: u32 = 0;
        GetExitCodeProcess(pi.hProcess, &mut exit_code);

        Ok(WaitOutput {
            stdout: "[Stdout capture pending in Low-IL Prototype]".to_string(),
            stderr: String::new(),
            exit_code: exit_code as i32,
        })
    }
}

#[cfg(not(windows))]
fn create_low_integrity_token() -> Result<windows_sys::Win32::Foundation::HANDLE, SandboxError> {
    Ok(0)
}

#[cfg(not(windows))]
fn spawn_low_integrity_process(
    _command: &str,
    _working_dir: &std::path::Path,
    _token: windows_sys::Win32::Foundation::HANDLE,
    _job: windows_sys::Win32::Foundation::HANDLE,
) -> Result<WaitOutput, SandboxError> {
    Err(SandboxError::NotAvailable("JobObjectSandbox requires Windows.".to_string()))
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
        // Since stdout capture is pending in the prototype, we check the placeholder
        assert!(output.stdout.contains("capture pending"));
    }

    #[test]
    fn test_windows_fail_closed_logic() {
        let sandbox = JobObjectSandbox;
        
        // 1. Invalid working directory should fail-closed during process creation
        let ctx_invalid_dir = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("NON_EXISTENT_DIR_12345"),
            timeout_ms: None,
        };
        let res = sandbox.execute("echo fail", &ctx_invalid_dir);
        assert!(res.is_err(), "Execution in non-existent directory should fail-closed");
        if let Err(e) = res {
            assert!(e.to_string().contains("CreateProcessAsUserW failed"));
        }

        // 2. Empty command should still be handled via fail-closed cmd /C
        let ctx_valid = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("."),
            timeout_ms: None,
        };
        let res_empty = sandbox.execute("", &ctx_valid);
        assert!(res_empty.is_ok(), "Empty command should execute cmd /C gracefully");
    }
}
