use crate::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult, SandboxCapabilities};
use std::path::Path;

/// Windows AppContainer sandbox.
/// 
/// **Experimental Prototype (Phase 7)**: Provides fine-grained isolation
/// using AppContainer SIDs. This is an opt-in alternative to Low-IL.
pub struct AppContainerSandbox;

impl Sandbox for AppContainerSandbox {
    fn name(&self) -> &'static str {
        "AppContainer"
    }

    fn sandbox_type(&self) -> &'static str {
        "windows-appcontainer"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: false, // AppContainer is more restrictive
            filesystem_write_workspace: true,
            filesystem_write_global: false,
            network_outbound_any: false,
            network_outbound_internet: true, // internetClient capability
            network_outbound_local: false,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    #[cfg(not(windows))]
    fn execute(&self, _command: &str, _context: &SandboxContext) -> SandboxResult {
        Err(SandboxError::NotAvailable("AppContainer requires Windows.".to_string()))
    }

    #[cfg(windows)]
    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        // Prototype implementation: focus on profile lifecycle and process setup.
        let profile_name = "AgentGuard_Sandbox_Profile";
        
        unsafe {
            self.execute_impl(command, context, profile_name)
        }
    }

    fn is_available(&self) -> bool {
        cfg!(windows)
    }
}

#[cfg(windows)]
impl AppContainerSandbox {
    unsafe fn execute_impl(&self, command: &str, context: &SandboxContext, profile_name: &str) -> SandboxResult {
        use windows::Win32::Security::Isolation::*;
        use windows::Win32::Security::*;
        use windows::Win32::System::Threading::*;
        use windows::Win32::Foundation::*;
        use windows::core::{PCWSTR, PWSTR};
        use std::os::windows::ffi::OsStrExt;

        // 1. Ensure Profile Exists
        let name_u16: Vec<u16> = std::ffi::OsStr::new(profile_name).encode_wide().chain(std::iter::once(0)).collect();
        let pcw_name = PCWSTR(name_u16.as_ptr());
        
        // Try creating/opening the profile (ignore error if exists)
        let _ = CreateAppContainerProfile(pcw_name, pcw_name, pcw_name, None, 0);
        
        // 2. Derive SID
        let sid = DeriveAppContainerSidFromAppContainerName(pcw_name)
            .map_err(|e| SandboxError::ExecutionFailed(format!("AppContainer: Failed to derive SID: {}", e)))?;
        
        // RAII for SID
        struct SidGuard(PSID);
        impl Drop for SidGuard {
            fn drop(&mut self) {
                unsafe { FreeSid(self.0); }
            }
        }
        let _sid_guard = SidGuard(sid);

        // 3. Setup Security Capabilities (internetClient)
        // S-1-15-3-1: internetClient
        let mut internet_client_sid: PSID = PSID::default();
        let ic_sid_str: Vec<u16> = std::ffi::OsStr::new("S-1-15-3-1").encode_wide().chain(std::iter::once(0)).collect();
        if !ConvertStringSidToSidW(PCWSTR(ic_sid_str.as_ptr()), &mut internet_client_sid).as_bool() {
            return Err(SandboxError::ExecutionFailed("AppContainer: Failed to build capability SID".to_string()));
        }
        let _ic_sid_guard = SidGuard(internet_client_sid);

        let mut caps = vec![SID_AND_ATTRIBUTES {
            Sid: internet_client_sid,
            Attributes: 0,
        }];

        let mut security_caps = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: caps.as_mut_ptr(),
            CapabilityCount: caps.len() as u32,
            Reserved: 0,
        };

        // 4. Prepare Startup Info with Attributes
        let mut size: usize = 0;
        let _ = InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut size);
        let mut buffer = vec![0u8; size];
        let attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr() as *mut _);
        
        InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut size)
            .map_err(|e| SandboxError::ExecutionFailed(format!("AppContainer: Failed to init attribute list: {}", e)))?;

        // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            0x00020009, 
            Some(&security_caps as *const _ as *const _),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        ).map_err(|e| SandboxError::ExecutionFailed(format!("AppContainer: Failed to update attribute: {}", e)))?;

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attribute_list;

        // 5. Spawn Process
        let cmd_string = format!("cmd /C \"{}\"", command);
        let mut cmd_vec: Vec<u16> = std::ffi::OsStr::new(&cmd_string).encode_wide().chain(std::iter::once(0)).collect();
        let mut working_dir_vec: Vec<u16> = context.working_directory.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        let mut pi = PROCESS_INFORMATION::default();

        let success = CreateProcessW(
            None,
            PWSTR(cmd_vec.as_mut_ptr()),
            None,
            None,
            true,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            None,
            PCWSTR(working_dir_vec.as_ptr()),
            &si.StartupInfo,
            &mut pi,
        );

        if !success.as_bool() {
            let err = GetLastError();
            return Err(SandboxError::ExecutionFailed(format!("AppContainer: CreateProcessW failed (code {}). Note: This often fails in prototypes if workspace ACLs are not yet set.", err.0)));
        }

        // Close handles (prototype just waits)
        let _ = CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        let mut exit_code: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);
        let _ = CloseHandle(pi.hProcess);

        Ok(SandboxOutput {
            stdout: "[AppContainer Prototype Executed]".to_string(),
            stderr: String::new(),
            exit_code: exit_code as i32,
        })
    }
}
