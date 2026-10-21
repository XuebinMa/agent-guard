//! Parent-side libseccomp compilation and allocation-free child installation.

#[cfg(test)]
use super::SetupFault;
use super::{configure_process_group, finish_child, SetupOptions};
use crate::seccomp_rules::{
    preflight_required_syscalls_with, resolve_required_syscall_with, COMMON_DENY_SYSCALLS,
    NETWORK_DENY_SYSCALLS, READ_ONLY_DENY_SYSCALLS, READ_ONLY_WRITE_FLAG_DENIES,
};
use crate::{SandboxContext, SandboxError, SandboxResult};
use agent_guard_core::PolicyMode;
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

const INSTRUCTION_BYTES: usize = 8;
const MAX_INSTRUCTIONS: usize = libc::BPF_MAXINSNS as usize;
const MAX_BPF_BYTES: usize = MAX_INSTRUCTIONS * INSTRUCTION_BYTES;
const NO_NEW_PRIVILEGES_STAGE: u32 = 1;
const INSTALL_FILTER_STAGE: u32 = 2;

pub(super) struct PreparedFilter {
    instructions: Vec<libc::sock_filter>,
}

pub(super) fn prepare_filter(
    mode: &PolicyMode,
    options: SetupOptions,
) -> Result<PreparedFilter, String> {
    let _ = options;
    // This must precede Command::spawn: a required name is never optional,
    // and its full diagnostic must not be reduced to errno by the exec pipe.
    preflight_required_syscalls_with(mode, |name| {
        #[cfg(test)]
        if matches!(options.fault, Some(SetupFault::MissingSyscall)) && name == "connect" {
            return Err("injected resolver failure".to_string());
        }
        ScmpSyscall::from_name(name).map_err(|error| error.to_string())
    })?;

    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)
        .map_err(|error| format!("failed to create seccomp filter: {error}"))?;
    filter
        .set_ctl_nnp(true)
        .map_err(|error| format!("failed to configure no_new_privs: {error}"))?;
    for name in NETWORK_DENY_SYSCALLS.iter().chain(COMMON_DENY_SYSCALLS) {
        add_deny_rule(&mut filter, name)?;
    }
    if matches!(mode, PolicyMode::ReadOnly) {
        for &(name, index) in READ_ONLY_WRITE_FLAG_DENIES {
            add_write_flag_denies(&mut filter, name, index)?;
        }
        for name in READ_ONLY_DENY_SYSCALLS {
            add_deny_rule(&mut filter, name)?;
        }
    }

    let instructions = export_filter(&filter)?;
    #[cfg(test)]
    let instructions = if matches!(options.fault, Some(SetupFault::InvalidFilter)) {
        // A real kernel verifier rejection, not a simulated libseccomp error.
        vec![libc::sock_filter {
            code: u16::MAX,
            jt: 0,
            jf: 0,
            k: 0,
        }]
    } else {
        instructions
    };
    Ok(PreparedFilter { instructions })
}

fn export_filter(filter: &ScmpFilterContext) -> Result<Vec<libc::sock_filter>, String> {
    // A private anonymous file avoids both path races and a blocking pipe
    // export. The raw syscall avoids requiring a newer glibc memfd symbol.
    // Hosts without memfd support (Linux <3.17) fail closed during preparation.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"agent-guard-seccomp-bpf".as_ptr(),
            libc::MFD_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(format!(
            "failed to create seccomp BPF export memfd: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: the successful syscall returned a new, exclusively owned fd.
    let mut file = unsafe { File::from_raw_fd(descriptor as RawFd) };
    filter
        .export_bpf(&mut file)
        .map_err(|error| format!("failed to export seccomp BPF: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("failed to rewind seccomp BPF: {error}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_BPF_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read seccomp BPF: {error}"))?;
    decode_filter(&bytes)
}

fn decode_filter(bytes: &[u8]) -> Result<Vec<libc::sock_filter>, String> {
    let invalid_length = || {
        format!(
            "invalid seccomp BPF length {}; expected 1..={MAX_INSTRUCTIONS} eight-byte instructions",
            bytes.len()
        )
    };
    if std::mem::size_of::<libc::sock_filter>() != INSTRUCTION_BYTES
        || bytes.is_empty()
        || bytes.len() > MAX_BPF_BYTES
    {
        return Err(invalid_length());
    }
    // libseccomp exports native-endian sock_filter fields. Decode into an
    // aligned Vec: casting the byte buffer would risk unaligned reads/UB.
    // split_first_chunk predates the current workspace MSRV.
    let mut remaining = bytes;
    let mut instructions = Vec::with_capacity(bytes.len() / INSTRUCTION_BYTES);
    while let Some((bytes, rest)) = remaining.split_first_chunk::<INSTRUCTION_BYTES>() {
        instructions.push(libc::sock_filter {
            code: u16::from_ne_bytes([bytes[0], bytes[1]]),
            jt: bytes[2],
            jf: bytes[3],
            k: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        });
        remaining = rest;
    }
    if !remaining.is_empty() {
        return Err(invalid_length());
    }
    Ok(instructions)
}

pub(super) fn execute_prepared(
    command: &str,
    context: &SandboxContext,
    filter: PreparedFilter,
    options: SetupOptions,
) -> SandboxResult {
    let (reader, writer) = failure_pipe().map_err(|error| {
        SandboxError::FilterSetup(format!(
            "failed to create seccomp setup report pipe: {error}"
        ))
    })?;
    let _ = options;
    let no_new_privileges: libc::c_ulong = 1;
    #[cfg(test)]
    let no_new_privileges = if matches!(options.fault, Some(SetupFault::NoNewPrivileges)) {
        2 // Invalid prctl argument: exercise the real errno/report path.
    } else {
        no_new_privileges
    };
    let mut child = Command::new("sh");
    child
        .arg("-c")
        .arg(command)
        .current_dir(&context.working_directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut child);
    // prepare_filter checked the count before fork; build the pointer-bearing
    // sock_fprog on the child stack, never a captured non-Send raw pointer.
    let count = filter.instructions.len() as libc::c_ushort;
    let instructions = filter.instructions;
    // SAFETY: the callback only reads preallocated immutable memory, invokes
    // raw system interfaces and creates errno-backed (nonallocating) errors.
    // No libseccomp, CString, formatting, logging, lock or destructor runs here.
    unsafe {
        child.pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                no_new_privileges,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) == -1
            {
                return Err(report_setup_failure(
                    writer.as_raw_fd(),
                    NO_NEW_PRIVILEGES_STAGE,
                ));
            }
            let program = libc::sock_fprog {
                len: count,
                filter: instructions.as_ptr().cast_mut(),
            };
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &program as *const libc::sock_fprog,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) == -1
            {
                return Err(report_setup_failure(
                    writer.as_raw_fd(),
                    INSTALL_FILTER_STAGE,
                ));
            }
            Ok(())
        });
    }
    let mut spawned = child.spawn();
    // The closure owns the parent's writer copy. Drop it before inspecting
    // the report; the child's copy is CLOEXEC and cannot reach the shell.
    drop(child);
    match read_setup_report(reader) {
        Ok(None) => {}
        report => {
            discard_spawned_child(&mut spawned);
            let message = match report {
                Ok(Some((stage, errno))) => {
                    let operation = match stage {
                        NO_NEW_PRIVILEGES_STAGE => "set no_new_privs",
                        INSTALL_FILTER_STAGE => "install seccomp BPF",
                        _ => unreachable!("report parser checked stage"),
                    };
                    format!(
                        "failed to {operation}: {}",
                        io::Error::from_raw_os_error(errno)
                    )
                }
                Err(error) => error,
                Ok(None) => unreachable!("handled above"),
            };
            return Err(SandboxError::FilterSetup(message));
        }
    }
    let child = spawned.map_err(|error| {
        SandboxError::ExecutionFailed(format!("Failed to spawn process: {error}"))
    })?;
    finish_child(child, context.timeout_ms)
}

fn failure_pipe() -> io::Result<(File, OwnedFd)> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 initialized two new owned descriptors on success.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let reader = above_stdio(reader)?;
    let writer = above_stdio(writer)?;
    Ok((File::from(reader), writer))
}

fn above_stdio(descriptor: OwnedFd) -> io::Result<OwnedFd> {
    if descriptor.as_raw_fd() > libc::STDERR_FILENO {
        return Ok(descriptor);
    }
    let duplicate = unsafe {
        libc::fcntl(
            descriptor.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            libc::STDERR_FILENO + 1,
        )
    };
    if duplicate == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new owned fd, safe from child stdio remapping.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn report_setup_failure(descriptor: RawFd, stage: u32) -> io::Error {
    // Capture errno before the reporting write can change it. Both error
    // constructors here retain raw errno and never allocate a custom payload.
    let error = io::Error::last_os_error();
    let errno = error.raw_os_error().unwrap_or(libc::EINVAL).to_ne_bytes();
    let stage = stage.to_ne_bytes();
    let record = [
        stage[0], stage[1], stage[2], stage[3], errno[0], errno[1], errno[2], errno[3],
    ];
    // One <=PIPE_BUF write to a fresh private pipe is atomic. EINTR is the
    // only retry; failure still returns the original hard error, never execs.
    loop {
        let written = unsafe { libc::write(descriptor, record.as_ptr().cast(), record.len()) };
        if written == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    error
}

fn read_setup_report(mut reader: File) -> Result<Option<(u32, i32)>, String> {
    // A concurrent host fork may briefly inherit a writer before its exec.
    // Nonblocking reads avoid waiting for an unrelated child to close it.
    let mut record = [0; 9];
    let mut count = 0;
    while count < record.len() {
        match reader.read(&mut record[count..]) {
            Ok(0) => break,
            Ok(read) => count += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(format!("failed to read seccomp setup report: {error}")),
        }
    }
    decode_setup_report(&record[..count])
}

fn decode_setup_report(record: &[u8]) -> Result<Option<(u32, i32)>, String> {
    if record.is_empty() {
        return Ok(None);
    }
    if record.len() != 8 {
        return Err("invalid seccomp setup report length".to_string());
    }
    let stage = u32::from_ne_bytes([record[0], record[1], record[2], record[3]]);
    let errno = i32::from_ne_bytes([record[4], record[5], record[6], record[7]]);
    if !matches!(stage, NO_NEW_PRIVILEGES_STAGE | INSTALL_FILTER_STAGE) || errno <= 0 {
        return Err("invalid seccomp setup report stage or errno".to_string());
    }
    Ok(Some((stage, errno)))
}

fn discard_spawned_child(spawned: &mut io::Result<Child>) {
    if let Ok(child) = spawned {
        // A malformed report must not orphan a successfully spawned command.
        // configure_process_group made the child's PID its process-group ID.
        let process_group = child.id() as libc::pid_t;
        let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn add_deny_rule(filter: &mut ScmpFilterContext, name: &str) -> Result<(), String> {
    let syscall = resolve_required_syscall_with(name, ScmpSyscall::from_name)?;
    filter
        .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
        .map_err(|error| format!("failed to add deny rule for {name}: {error}"))
}

fn add_write_flag_denies(
    filter: &mut ScmpFilterContext,
    name: &str,
    index: u32,
) -> Result<(), String> {
    let syscall = resolve_required_syscall_with(name, ScmpSyscall::from_name)?;
    let deny = ScmpAction::Errno(libc::EPERM);
    for access_mode in [libc::O_WRONLY, libc::O_RDWR] {
        filter
            .add_rule_conditional(
                deny,
                syscall,
                &[ScmpArgCompare::new(
                    index,
                    ScmpCompareOp::MaskedEqual(libc::O_ACCMODE as u64),
                    access_mode as u64,
                )],
            )
            .map_err(|error| format!("failed to add {name} access-mode deny rule: {error}"))?;
    }
    for flag in [libc::O_CREAT, libc::O_TRUNC, libc::O_APPEND] {
        filter
            .add_rule_conditional(
                deny,
                syscall,
                &[ScmpArgCompare::new(
                    index,
                    ScmpCompareOp::MaskedEqual(flag as u64),
                    flag as u64,
                )],
            )
            .map_err(|error| format!("failed to add {name} flag deny rule: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_seccomp_tests.rs"]
mod tests;
