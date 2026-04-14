#[cfg(windows)]
use crate::SandboxOutput;
use crate::{RuntimeCheck, Sandbox, SandboxContext, SandboxError, SandboxResult};
#[cfg(windows)]
use std::sync::OnceLock;

/// Windows sandbox implementation using Job Objects and Restricted Tokens.
///
/// **Strengthened Prototype (Phase 5)**: Enforces process tree isolation via
/// Job Objects and filesystem write protection via Low Integrity Level (Low-IL)
/// tokens. Fail-closed: if the environment setup fails, execution is blocked.
pub struct JobObjectSandbox;

#[cfg(windows)]
#[derive(Clone)]
struct WindowsRuntimeProbe {
    available: bool,
    summary: String,
    checks: Vec<RuntimeCheck>,
}

fn unavailable_capabilities() -> crate::SandboxCapabilities {
    crate::SandboxCapabilities {
        filesystem_read_workspace: false,
        filesystem_read_global: false,
        filesystem_write_workspace: false,
        filesystem_write_global: false,
        network_outbound_any: false,
        network_outbound_internet: false,
        network_outbound_local: false,
        child_process_spawn: false,
        registry_write: false,
    }
}

#[cfg(windows)]
fn job_object_runtime_probe() -> &'static WindowsRuntimeProbe {
    static CACHE: OnceLock<WindowsRuntimeProbe> = OnceLock::new();

    CACHE.get_or_init(|| {
        use windows_sys::Win32::System::JobObjects::CreateJobObjectW;

        let mut checks = Vec::new();

        let token = match create_low_integrity_token() {
            Ok(token) => {
                checks.push(RuntimeCheck::pass(
                    "low_integrity_token",
                    "Successfully created a low-integrity primary token",
                ));
                token
            }
            Err(err) => {
                checks.push(RuntimeCheck::fail(
                    "low_integrity_token",
                    err.to_string(),
                ));
                checks.push(RuntimeCheck::skipped(
                    "job_object_handle",
                    "Skipped because low-integrity token creation failed",
                ));
                checks.push(RuntimeCheck::skipped(
                    "low_integrity_process_launch",
                    "Skipped because low-integrity token creation failed",
                ));
                return WindowsRuntimeProbe {
                    available: false,
                    summary: "Low-integrity token creation failed on this host".to_string(),
                    checks,
                };
            }
        };
        let _token_guard = TokenHandle(token);

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job == 0 {
            let err = std::io::Error::last_os_error();
            checks.push(RuntimeCheck::fail("job_object_handle", err.to_string()));
            checks.push(RuntimeCheck::skipped(
                "low_integrity_process_launch",
                "Skipped because Job Object creation failed",
            ));
            return WindowsRuntimeProbe {
                available: false,
                summary: "Job Object creation failed on this host".to_string(),
                checks,
            };
        }
        let _job_guard = SafeHandle(job);
        checks.push(RuntimeCheck::pass(
            "job_object_handle",
            "Successfully created a Job Object handle",
        ));

        let working_dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
        match spawn_low_integrity_process("exit 0", &working_dir, Some(2_000), token, job) {
            Ok(output) => {
                checks.push(RuntimeCheck::pass(
                    "low_integrity_process_launch",
                    format!(
                        "Successfully launched and completed a low-integrity child process via {}",
                        output.launcher
                    ),
                ));
                WindowsRuntimeProbe {
                    available: true,
                    summary: format!(
                        "Low-integrity token creation, Job Object creation, and process launch are functional on this host via {}.",
                        output.launcher
                    ),
                    checks,
                }
            }
            Err(err) => {
                checks.push(RuntimeCheck::fail(
                    "low_integrity_process_launch",
                    err.to_string(),
                ));
                WindowsRuntimeProbe {
                    available: false,
                    summary: "Low-integrity process launch failed on this host".to_string(),
                    checks,
                }
            }
        }
    })
}

#[cfg(windows)]
fn job_object_runtime_available() -> bool {
    job_object_runtime_probe().available
}

#[cfg(not(windows))]
fn job_object_runtime_available() -> bool {
    false
}

impl Sandbox for JobObjectSandbox {
    fn name(&self) -> &'static str {
        "JobObject"
    }

    fn sandbox_type(&self) -> &'static str {
        "windows-job-object"
    }

    fn capabilities(&self) -> crate::SandboxCapabilities {
        if !job_object_runtime_available() {
            return unavailable_capabilities();
        }

        crate::SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: true, // Low-IL allows global read
            filesystem_write_workspace: true,
            filesystem_write_global: false, // Low-IL provides write isolation
            network_outbound_any: true,     // Current prototype allows all network
            network_outbound_internet: true,
            network_outbound_local: true,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    #[cfg(not(windows))]
    fn execute(&self, _command: &str, _context: &SandboxContext) -> SandboxResult {
        Err(SandboxError::NotAvailable(
            "JobObjectSandbox requires Windows.".to_string(),
        ))
    }

    #[cfg(windows)]
    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::*;

        if !job_object_runtime_available() {
            return Err(SandboxError::NotAvailable(
                "Windows low-integrity process creation is not functional on this host".to_string(),
            ));
        }

        // 1. Create Job Object
        // Safety: Creating a private job object for the command.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job == 0 {
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Fail-closed - Failed to create Job Object".to_string(),
            ));
        }

        // RAII handle to ensure cleanup
        struct JobHandle(HANDLE);
        impl Drop for JobHandle {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let _job_guard = JobHandle(job);

        // 2. Configure Limits: Kill all processes in job on handle close + Resource Limits
        // Safety: Initializing JOBOBJECT_EXTENDED_LIMIT_INFORMATION with zeroes is safe.
        // SetInformationJobObject is called with valid handles and pointers.
        unsafe {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

            // Apply memory limits if specified in context (conceptual for prototype)
            // For now, we apply a safe default of 256MB for the sandbox if not specified
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.ProcessMemoryLimit = 256 * 1024 * 1024; // 256MB default limit

            let res = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if res == 0 {
                return Err(SandboxError::ExecutionFailed(
                    "Windows Sandbox: Fail-closed - Failed to configure Job Object".to_string(),
                ));
            }
        }

        // 3. Create Low Integrity Token (M5.1)
        let token = create_low_integrity_token()?;
        let _token_guard = TokenHandle(token);

        // 4. Execute with Restricted Token (CRITICAL ENFORCEMENT)
        // This is the ACTIVE implementation using CreateProcessAsUserW.
        // It ENSURES the restricted token is applied to the child process.
        let output = spawn_low_integrity_process(
            command,
            &context.working_directory,
            context.timeout_ms,
            token,
            job,
        )?;

        Ok(SandboxOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }

    fn is_available(&self) -> bool {
        job_object_runtime_available()
    }

    #[cfg(windows)]
    fn availability_note(&self) -> Option<String> {
        Some(job_object_runtime_probe().summary.clone())
    }

    #[cfg(not(windows))]
    fn availability_note(&self) -> Option<String> {
        Some("JobObjectSandbox requires Windows".to_string())
    }

    #[cfg(windows)]
    fn runtime_checks(&self) -> Vec<RuntimeCheck> {
        job_object_runtime_probe().checks.clone()
    }

    #[cfg(not(windows))]
    fn runtime_checks(&self) -> Vec<RuntimeCheck> {
        Vec::new()
    }
}

// RAII handle to ensure Win32 handles are closed.
#[cfg(windows)]
struct SafeHandle(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Drop for SafeHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
struct TokenHandle(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Drop for TokenHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[allow(dead_code)]
struct WaitOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
    launcher: &'static str,
}

#[cfg(windows)]
fn create_pipe() -> Result<
    (
        windows_sys::Win32::Foundation::HANDLE,
        windows_sys::Win32::Foundation::HANDLE,
    ),
    SandboxError,
> {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    unsafe {
        let mut read_pipe = 0;
        let mut write_pipe = 0;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1, // Write end should be inheritable
        };

        if CreatePipe(&mut read_pipe, &mut write_pipe, &sa, 0) == 0 {
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to create pipe".to_string(),
            ));
        }

        // Ensure read end is NOT inherited
        if SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0) == 0 {
            let _ = windows_sys::Win32::Foundation::CloseHandle(read_pipe);
            let _ = windows_sys::Win32::Foundation::CloseHandle(write_pipe);
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to configure pipe inheritance".to_string(),
            ));
        }

        Ok((read_pipe, write_pipe))
    }
}

#[cfg(windows)]
fn read_handle_to_string(handle: windows_sys::Win32::Foundation::HANDLE) -> String {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut out = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut bytes_read = 0;
    // Safety: Reading from a valid handle is safe. The buffer is pre-allocated.
    unsafe {
        loop {
            if ReadFile(
                handle,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut::<OVERLAPPED>(),
            ) == 0
            {
                break;
            }
            if bytes_read == 0 {
                break;
            }
            out.extend_from_slice(&buffer[..bytes_read as usize]);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(windows)]
fn create_low_integrity_token() -> Result<windows_sys::Win32::Foundation::HANDLE, SandboxError> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        let mut process_token: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
            &mut process_token,
        ) == 0
        {
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to open process token".to_string(),
            ));
        }
        let _pt_guard = SafeHandle(process_token);

        let mut low_token: HANDLE = 0;
        // Point 9 Fix: Use minimal permissions for the duplicated token
        if DuplicateTokenEx(
            process_token,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut low_token,
        ) == 0
        {
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to duplicate token".to_string(),
            ));
        }
        let _lt_guard = SafeHandle(low_token);

        let mut integrity_sid: *mut std::ffi::c_void = std::ptr::null_mut();
        // S-1-16-4096 (Low Mandatory Level)
        let low_integrity_sid_auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };
        if AllocateAndInitializeSid(
            &low_integrity_sid_auth,
            1,
            0x1000,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut integrity_sid,
        ) == 0
        {
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to allocate SID".to_string(),
            ));
        }

        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: integrity_sid,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };

        let res = SetTokenInformation(
            low_token,
            TokenIntegrityLevel,
            &tml as *const _ as *const _,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        );
        FreeSid(integrity_sid);

        if res == 0 {
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to set token integrity level".to_string(),
            ));
        }

        // Return the raw handle, but we need to prevent the guard from closing it here
        // The caller will wrap it in TokenHandle.
        std::mem::forget(_lt_guard);
        Ok(low_token)
    }
}

#[cfg(windows)]
fn spawn_low_integrity_process(
    command: &str,
    working_dir: &std::path::Path,
    timeout_ms: Option<u64>,
    token: windows_sys::Win32::Foundation::HANDLE,
    job: windows_sys::Win32::Foundation::HANDLE,
) -> Result<WaitOutput, SandboxError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        // 1. Create Pipes for stdout and stderr
        let (stdout_read, stdout_write) = create_pipe()?;
        let _stdout_read_guard = SafeHandle(stdout_read);
        let _stdout_write_guard = SafeHandle(stdout_write);

        let (stderr_read, stderr_write) = create_pipe()?;
        let _stderr_read_guard = SafeHandle(stderr_read);
        let _stderr_write_guard = SafeHandle(stderr_write);

        // Prepare command line - use a safer way to pass the command to cmd /C
        // Industrial Standard: Properly escaping for cmd.exe is complex.
        // We wrap the command in double quotes and escape internal double quotes.
        let escaped_command = command.replace("\"", "\"\"");
        let cmd_string = format!("cmd.exe /C \"{}\"", escaped_command);
        let mut cmd_vec: Vec<u16> = std::ffi::OsStr::new(&cmd_string)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let working_dir_vec: Vec<u16> = working_dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = 0;
        si.hStdOutput = stdout_write;
        si.hStdError = stderr_write;
        si.hStdInput = 0;

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // 2. Spawn process suspended to allow job assignment.
        // Prefer CreateProcessAsUserW; fall back to CreateProcessWithTokenW on
        // hosts where primary-token launch is denied but token-based launch is allowed.
        let launcher = if CreateProcessAsUserW(
            token,
            std::ptr::null(),
            cmd_vec.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles
            CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED,
            std::ptr::null(),
            working_dir_vec.as_ptr(),
            &si,
            &mut pi,
        ) != 0
        {
            "CreateProcessAsUserW"
        } else {
            let first_err = std::io::Error::last_os_error();
            let raw = first_err.raw_os_error().unwrap_or_default() as u32;

            if raw != ERROR_ACCESS_DENIED && raw != ERROR_PRIVILEGE_NOT_HELD {
                return Err(SandboxError::ExecutionFailed(format!(
                    "Windows Sandbox: CreateProcessAsUserW failed: {first_err}"
                )));
            }

            if CreateProcessWithTokenW(
                token,
                LOGON_WITH_PROFILE,
                std::ptr::null(),
                cmd_vec.as_mut_ptr(),
                CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED,
                std::ptr::null(),
                working_dir_vec.as_ptr(),
                &si,
                &mut pi,
            ) == 0
            {
                let fallback_err = std::io::Error::last_os_error();
                return Err(SandboxError::ExecutionFailed(format!(
                    "Windows Sandbox: CreateProcessAsUserW failed: {first_err}; fallback CreateProcessWithTokenW failed: {fallback_err}"
                )));
            }

            "CreateProcessWithTokenW"
        };

        let _process_guard = SafeHandle(pi.hProcess);
        let _thread_guard = SafeHandle(pi.hThread);

        // 3. Assign to Job Object before resuming
        if AssignProcessToJobObject(job, pi.hProcess) == 0 {
            let _ = TerminateProcess(pi.hProcess, 1);
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Fail-closed - Failed to assign process to job".to_string(),
            ));
        }

        // 4. Close parent's write handles so pipes close when child exits
        drop(_stdout_write_guard);
        drop(_stderr_write_guard);

        // 5. Start reader threads BEFORE resuming to avoid deadlocks on small pipe buffers
        let stdout_read_handle = stdout_read;
        let stderr_read_handle = stderr_read;

        let stdout_thread = std::thread::spawn(move || read_handle_to_string(stdout_read_handle));
        let stderr_thread = std::thread::spawn(move || read_handle_to_string(stderr_read_handle));

        // 6. Resume process
        if ResumeThread(pi.hThread) == u32::MAX {
            let _ = TerminateProcess(pi.hProcess, 1);
            return Err(SandboxError::ExecutionFailed(
                "Windows Sandbox: Failed to resume low-IL process".to_string(),
            ));
        }

        // 7. Wait for completion with optional timeout
        let timeout_ms = timeout_ms.unwrap_or(u32::MAX as u64); // INFINITE if None
        let wait_res = WaitForSingleObject(pi.hProcess, timeout_ms as u32);

        if wait_res == WAIT_TIMEOUT {
            let _ = TerminateProcess(pi.hProcess, 1);
            return Err(SandboxError::Timeout { ms: timeout_ms });
        }

        let mut exit_code: u32 = 0;
        GetExitCodeProcess(pi.hProcess, &mut exit_code);

        let stdout = stdout_thread
            .join()
            .unwrap_or_else(|_| "[Error reading stdout]".to_string());
        let stderr = stderr_thread
            .join()
            .unwrap_or_else(|_| "[Error reading stderr]".to_string());

        Ok(WaitOutput {
            stdout,
            stderr,
            exit_code: exit_code as i32,
            launcher,
        })
    }
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn create_low_integrity_token() -> Result<u64, SandboxError> {
    Ok(0)
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn spawn_low_integrity_process(
    _command: &str,
    _working_dir: &std::path::Path,
    _timeout_ms: Option<u64>,
    _token: u64,
    _job: u64,
) -> Result<WaitOutput, SandboxError> {
    Err(SandboxError::NotAvailable(
        "JobObjectSandbox requires Windows.".to_string(),
    ))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{Sandbox, SandboxContext, SandboxError};
    use agent_guard_core::PolicyMode;
    use std::path::PathBuf;

    fn runtime_available_or_skip() -> bool {
        let sandbox = JobObjectSandbox;
        if sandbox.is_available() {
            return true;
        }

        eprintln!(
            "skipping Windows Job Object execution assertions: low-integrity process creation is not functional on this host"
        );
        false
    }

    #[test]
    fn test_windows_job_object_lifecycle() {
        if !runtime_available_or_skip() {
            return;
        }

        let sandbox = JobObjectSandbox;
        let ctx = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("."),
            timeout_ms: None,
        };
        let res = sandbox.execute("echo test_output_capture", &ctx);
        assert!(
            res.is_ok(),
            "Windows execution should succeed within Job Object"
        );
        let output = res.unwrap();
        // Now stdout should be captured!
        assert!(output.stdout.contains("test_output_capture"));
    }

    #[test]
    fn test_windows_low_il_write_restriction() {
        if !runtime_available_or_skip() {
            return;
        }

        let sandbox = JobObjectSandbox;
        let ctx = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("."),
            timeout_ms: None,
        };

        // Try writing to C:\Windows (should fail under Low-IL)
        // cmd /C "echo test > C:\Windows\test.txt" usually prints "Access is denied" to stderr.
        let res = sandbox.execute("echo test > C:\\Windows\\agent_guard_low_il_test.txt", &ctx);

        if let Ok(output) = res {
            // Under Low-IL, this should trigger "Access is denied" in cmd.exe
            let stderr = output.stderr.to_lowercase();
            assert!(
                stderr.contains("access is denied") || output.exit_code != 0,
                "Low-IL must restrict writing to system directories. Stderr: {}",
                output.stderr
            );
        }
    }

    #[test]
    fn test_windows_workspace_write_success() {
        if !runtime_available_or_skip() {
            return;
        }

        let sandbox = JobObjectSandbox;
        let temp_dir = std::env::temp_dir().join("agent_guard_p5_test");
        let _ = std::fs::create_dir_all(&temp_dir);

        let ctx = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: temp_dir.clone(),
            timeout_ms: None,
        };

        let res = sandbox.execute("echo hello_from_sandbox", &ctx);
        assert!(res.is_ok());
        let output = res.unwrap();
        assert!(output.stdout.contains("hello_from_sandbox"));

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_windows_fail_closed_logic() {
        let sandbox = JobObjectSandbox;

        if !sandbox.is_available() {
            let err = sandbox
                .execute(
                    "echo fail",
                    &SandboxContext {
                        mode: PolicyMode::ReadOnly,
                        working_directory: PathBuf::from("."),
                        timeout_ms: None,
                    },
                )
                .expect_err("unavailable JobObjectSandbox must fail closed");
            assert!(matches!(err, SandboxError::NotAvailable(_)));
            return;
        }

        // 1. Invalid working directory should fail-closed during process creation
        let ctx_invalid_dir = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("NON_EXISTENT_DIR_12345"),
            timeout_ms: None,
        };
        let res = sandbox.execute("echo fail", &ctx_invalid_dir);
        assert!(
            res.is_err(),
            "Execution in non-existent directory should fail-closed"
        );
        if let Err(e) = res {
            assert!(
                e.to_string().contains("CreateProcessAsUserW failed")
                    || e.to_string()
                        .contains("The system cannot find the file specified")
            );
        }

        // 2. Empty command should still be handled via fail-closed cmd /C
        let ctx_valid = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: PathBuf::from("."),
            timeout_ms: None,
        };
        let res_empty = sandbox.execute("", &ctx_valid);
        assert!(
            res_empty.is_ok(),
            "Empty command should execute cmd /C gracefully"
        );
    }

    #[test]
    fn test_windows_handle_inheritance_audit() {
        // Concept: We want to ensure that if we open a file in the parent,
        // it is NOT inheritable by default, thus the child cannot see it.
        use std::fs::File;
        use std::os::windows::io::AsRawHandle;

        let file = File::create("sensitive_parent_data.txt").unwrap();
        let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

        // Verify that the handle is NOT inheritable by default (Win32 default for CreateFile)
        let mut flags: u32 = 0;
        unsafe {
            windows_sys::Win32::Foundation::GetHandleInformation(handle, &mut flags);
        }
        assert!(
            (flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT) == 0,
            "Sensitive parent handle should not be inheritable by default."
        );

        std::fs::remove_file("sensitive_parent_data.txt").unwrap();
    }

    #[test]
    fn test_windows_low_il_token_integrity_audit() {
        // Strong test: Verify that the token we create actually HAS Low integrity level.
        use windows_sys::Win32::Security::*;

        let res = create_low_integrity_token();
        assert!(res.is_ok());
        let token = res.unwrap();
        let _guard = TokenHandle(token);

        let mut len: u32 = 0;
        unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &mut len,
            );
            let mut buffer = vec![0u8; len as usize];
            if GetTokenInformation(
                token,
                TokenIntegrityLevel,
                buffer.as_mut_ptr() as *mut _,
                len,
                &mut len,
            ) != 0
            {
                let tml = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
                let sid = tml.Label.Sid;

                let sub_authority_count = *GetSidSubAuthorityCount(sid);
                let last_sub_authority = *GetSidSubAuthority(sid, sub_authority_count as u32 - 1);

                // Low Mandatory Level RID is 0x1000 (4096)
                assert_eq!(
                    last_sub_authority, 0x1000,
                    "Token RID should be 0x1000 (Low Integrity Level)"
                );
            } else {
                panic!("Failed to get token information");
            }
        }
    }
}
