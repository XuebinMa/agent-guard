//! Shared child-process lifecycle for Unix sandbox backends and the noop
//! runner.
//!
//! Pipes are drained concurrently with a fixed retention limit. On Unix each
//! command starts a new session, allowing timeout/resource cleanup to target
//! the complete process group instead of only the shell process.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{SandboxError, OUTPUT_CAPTURE_LIMIT_BYTES};

const STDOUT_LIMIT_BIT: u8 = 1;
const STDERR_LIMIT_BIT: u8 = 2;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

// Stop readers on every error/early return as well as an ordinary timeout.
// Unix pipe reads are nonblocking, so no live writer can prevent cancellation.
struct CancelReaders(Arc<AtomicBool>);

impl Drop for CancelReaders {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(unix)]
fn prepare_output_reader(reader: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = reader.as_raw_fd();
    // SAFETY: fd is owned by the live pipe, and flags only affect its read end.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_output_reader(_reader: &impl Read) -> io::Result<()> {
    Ok(())
}

#[derive(Debug)]
pub(crate) struct CapturedChild {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) status: ExitStatus,
}

/// Prepare a Unix sandbox child for bounded lifecycle ownership.
///
/// The child and descendants live in a fresh session/process group, and every
/// inherited descriptor above stderr is marked close-on-exec. Path-oriented
/// sandboxes cannot revoke authority already attached to a descriptor opened
/// before their policy is installed, so carrying ambient descriptors into the
/// executed shell would bypass the claimed filesystem boundary.
///
/// Multiple `pre_exec` callbacks are supported, so a backend may add its
/// seccomp/Landlock setup after this callback.
#[cfg(unix)]
pub(crate) fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: this callback only invokes async-signal-safe system interfaces
    // and touches stack/captured scalar state. A failure aborts spawning
    // instead of running with either ambient descriptors or no tree ownership.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            mark_non_stdio_descriptors_close_on_exec()
        });
    }
}

#[cfg(not(unix))]
pub(crate) fn configure_process_group(_command: &mut Command) {}

#[cfg(target_os = "linux")]
fn mark_non_stdio_descriptors_close_on_exec() -> io::Result<()> {
    // Linux 5.11 added CLOSE_RANGE_CLOEXEC; Landlock itself requires 5.13 and
    // current seccomp deployments use the same fast path. The raw syscall
    // avoids a dependency on the host glibc exporting close_range(2).
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOSYS) && error.raw_os_error() != Some(libc::EINVAL) {
        return Err(error);
    }

    // CLOSE_RANGE_CLOEXEC arrived after the original close_range syscall.
    // Preserve the documented older-seccomp-kernel compatibility with a
    // slower async-signal-safe fallback rather than silently inheriting FDs.
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let limit = unsafe { limit.assume_init() }.rlim_cur;
    if limit == libc::RLIM_INFINITY || limit > libc::c_int::MAX as libc::rlim_t {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }
    mark_descriptor_range_close_on_exec(limit as libc::c_int)
}

#[cfg(target_os = "linux")]
fn mark_descriptor_range_close_on_exec(upper_bound: libc::c_int) -> io::Result<()> {
    for descriptor in (libc::STDERR_FILENO + 1)..upper_bound {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn mark_non_stdio_descriptors_close_on_exec() -> io::Result<()> {
    const MAX_TRACKED_DESCRIPTORS: usize = 4_096;

    // macOS has no close_range(2). Query the post-fork child itself so file
    // descriptors opened concurrently in the parent before fork cannot evade
    // the snapshot. A fixed stack buffer keeps this pre-exec callback free of
    // allocation; unusually descriptor-heavy hosts fail closed.
    let mut descriptors =
        std::mem::MaybeUninit::<[libc::proc_fdinfo; MAX_TRACKED_DESCRIPTORS]>::uninit();
    let required = list_current_macos_descriptors(std::ptr::null_mut(), 0);
    if required < 0 {
        return Err(io::Error::last_os_error());
    }
    if required as usize > std::mem::size_of_val(&descriptors) {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }

    let listed = list_current_macos_descriptors(
        descriptors.as_mut_ptr().cast(),
        std::mem::size_of_val(&descriptors) as libc::c_int,
    );
    if listed < 0 {
        return Err(io::Error::last_os_error());
    }

    let descriptor_count = listed as usize / std::mem::size_of::<libc::proc_fdinfo>();
    if descriptor_count > MAX_TRACKED_DESCRIPTORS {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    let descriptor_ptr = descriptors.as_ptr().cast::<libc::proc_fdinfo>();
    for index in 0..descriptor_count {
        // SAFETY: proc_pidinfo initialized exactly `listed` bytes, and the
        // bounds above keep this read within that initialized prefix.
        let descriptor = unsafe { descriptor_ptr.add(index).read() };
        if descriptor.proc_fd <= libc::STDERR_FILENO {
            continue;
        }
        let flags = unsafe { libc::fcntl(descriptor.proc_fd, libc::F_GETFD) };
        if flags == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
        if unsafe { libc::fcntl(descriptor.proc_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn list_current_macos_descriptors(
    buffer: *mut libc::c_void,
    buffer_size: libc::c_int,
) -> libc::c_int {
    // proc_pidinfo(3) is a thin wrapper over this XNU syscall. Calling it
    // directly keeps the post-fork callback within an async-signal-safe kernel
    // interface instead of entering libproc. Constants come from the shipped
    // macOS SDK's sys/syscall.h and sys/proc_info.h.
    const SYS_PROC_INFO: libc::c_int = 336;
    const PROC_INFO_CALL_PIDINFO: libc::c_int = 2;

    unsafe {
        libc::syscall(
            SYS_PROC_INFO,
            PROC_INFO_CALL_PIDINFO,
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0_u64,
            buffer,
            buffer_size,
        )
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn mark_non_stdio_descriptors_close_on_exec() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor hygiene is not implemented on this Unix platform",
    ))
}

pub(crate) fn wait_for_child(
    mut child: Child,
    timeout_ms: Option<u64>,
) -> Result<CapturedChild, SandboxError> {
    let deadline = match timeout_ms {
        Some(timeout_ms) => match Instant::now().checked_add(Duration::from_millis(timeout_ms)) {
            Some(deadline) => Some(deadline),
            None => {
                let _ = terminate_process_tree(&mut child);
                let _ = child.wait();
                return Err(SandboxError::ExecutionFailed(
                    "sandbox timeout exceeds the platform clock range".to_string(),
                ));
            }
        },
        None => None,
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = terminate_process_tree(&mut child);
            let _ = child.wait();
            return Err(SandboxError::ExecutionFailed(
                "sandbox child stdout was not piped".to_string(),
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let _ = terminate_process_tree(&mut child);
            let _ = child.wait();
            return Err(SandboxError::ExecutionFailed(
                "sandbox child stderr was not piped".to_string(),
            ));
        }
    };

    if let Err(error) = prepare_output_reader(&stdout).and_then(|_| prepare_output_reader(&stderr))
    {
        let _ = terminate_process_tree(&mut child);
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::ExecutionFailed(format!(
            "failed to prepare output capture: {error}"
        )));
    }
    let cancel = CancelReaders(Arc::new(AtomicBool::new(false)));
    let stdout_cancel = Arc::clone(&cancel.0);
    let stderr_cancel = Arc::clone(&cancel.0);
    let limit_flags = Arc::new(AtomicU8::new(0));
    let stdout_flags = Arc::clone(&limit_flags);
    let stderr_flags = Arc::clone(&limit_flags);
    let stdout_thread =
        thread::spawn(move || read_bounded(stdout, STDOUT_LIMIT_BIT, stdout_flags, stdout_cancel));
    let stderr_thread =
        thread::spawn(move || read_bounded(stderr, STDERR_LIMIT_BIT, stderr_flags, stderr_cancel));

    let mut status = None;
    let mut terminal_error = None;

    loop {
        let exceeded = limit_flags.load(Ordering::Acquire);
        if terminal_error.is_none() && exceeded != 0 {
            terminal_error = Some(output_limit_error(exceeded));
            if let Err(error) = terminate_process_tree(&mut child) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::ExecutionFailed(format!(
                    "failed to terminate process tree after output limit: {error}"
                )));
            }
        }

        if terminal_error.is_none() && deadline.is_some_and(|end| Instant::now() >= end) {
            terminal_error = Some(SandboxError::Timeout {
                ms: timeout_ms.expect("deadline implies timeout"),
            });
            if let Err(error) = terminate_process_tree(&mut child) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::ExecutionFailed(format!(
                    "failed to terminate process tree after timeout: {error}"
                )));
            }
        }

        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    cancel.0.store(true, Ordering::Release);
                    let _ = terminate_process_tree(&mut child);
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_reader(stdout_thread, "stdout");
                    let _ = join_reader(stderr_thread, "stderr");
                    return Err(SandboxError::ExecutionFailed(format!(
                        "failed to poll sandbox child: {error}"
                    )));
                }
            };
            if status.is_some() {
                // A shell may exit after putting a descendant in the
                // background. Close that escape before waiting for pipe EOF.
                if let Err(error) = terminate_remaining_process_group(&child) {
                    return Err(SandboxError::ExecutionFailed(format!(
                        "failed to terminate remaining process-group members: {error}"
                    )));
                }
            }
        }

        if terminal_error.is_some() && status.is_none() {
            cancel.0.store(true, Ordering::Release);
            status = match child.wait() {
                Ok(status) => Some(status),
                Err(error) => {
                    let _ = join_reader(stdout_thread, "stdout");
                    let _ = join_reader(stderr_thread, "stderr");
                    return Err(SandboxError::ExecutionFailed(format!(
                        "failed to reap sandbox child: {error}"
                    )));
                }
            };
        }

        if terminal_error.is_some() {
            cancel.0.store(true, Ordering::Release);
        }

        if status.is_some() && stdout_thread.is_finished() && stderr_thread.is_finished() {
            break;
        }

        thread::sleep(POLL_INTERVAL);
    }

    let stdout = join_reader(stdout_thread, "stdout")?;
    let stderr = join_reader(stderr_thread, "stderr")?;
    if let Some(error) = terminal_error {
        return Err(error);
    }
    let exceeded = limit_flags.load(Ordering::Acquire);
    if exceeded != 0 {
        return Err(output_limit_error(exceeded));
    }

    Ok(CapturedChild {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        status: status.expect("loop exits only after child status is available"),
    })
}

fn read_bounded(
    mut reader: impl Read,
    stream_bit: u8,
    limit_flags: Arc<AtomicU8>,
    cancel: Arc<AtomicBool>,
) -> io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];

    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(retained);
        }
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Ok(retained);
        }

        let remaining = OUTPUT_CAPTURE_LIMIT_BYTES.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
        if read > remaining {
            limit_flags.fetch_or(stream_bit, Ordering::Release);
        }
    }
}

fn join_reader(
    handle: thread::JoinHandle<io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<Vec<u8>, SandboxError> {
    handle
        .join()
        .map_err(|_| SandboxError::ExecutionFailed(format!("{stream} reader thread panicked")))?
        .map_err(|error| {
            SandboxError::ExecutionFailed(format!("failed to read child {stream}: {error}"))
        })
}

fn output_limit_error(flags: u8) -> SandboxError {
    let stream = match flags & (STDOUT_LIMIT_BIT | STDERR_LIMIT_BIT) {
        STDOUT_LIMIT_BIT => "stdout",
        STDERR_LIMIT_BIT => "stderr",
        _ => "stdout and stderr",
    };
    SandboxError::OutputLimitExceeded {
        stream: stream.to_string(),
        limit_bytes: OUTPUT_CAPTURE_LIMIT_BYTES,
    }
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) -> io::Result<()> {
    let process_group = i32::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "child PID exceeds pid_t"))?;
    // SAFETY: a negative PID addresses the dedicated process group established
    // by `configure_process_group`; SIGKILL cannot be caught or ignored.
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        // The group may have exited between the poll and the signal.
        return Ok(());
    }
    Err(error)
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut Child) -> io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn terminate_remaining_process_group(child: &Child) -> io::Result<()> {
    let process_group = i32::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "child PID exceeds pid_t"))?;
    // SAFETY: see `terminate_process_tree`; ESRCH means no descendant remains.
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
fn terminate_remaining_process_group(_child: &Child) -> io::Result<()> {
    Ok(())
}

pub(crate) fn shell_command(command: &str) -> Command {
    #[cfg(windows)]
    {
        let mut shell = Command::new("cmd.exe");
        shell.arg("/C").arg(command);
        shell
    }
    #[cfg(not(windows))]
    {
        let mut shell = Command::new("sh");
        shell.arg("-c").arg(command);
        shell
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{configure_process_group, shell_command, wait_for_child};
    use crate::{SandboxError, OUTPUT_CAPTURE_LIMIT_BYTES};
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    use std::time::Duration;

    fn spawn(command: &str) -> std::process::Child {
        let mut command = shell_command(command);
        configure_process_group(&mut command);
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn test child")
    }

    #[test]
    fn captures_both_streams_without_waiting_for_pipe_capacity() {
        let output = wait_for_child(
            spawn("i=0; while [ $i -lt 20000 ]; do echo out; echo err >&2; i=$((i+1)); done"),
            Some(5_000),
        )
        .expect("capture output");
        assert!(output.status.success());
        assert!(output.stdout.len() > 64 * 1024);
        assert!(output.stderr.len() > 64 * 1024);
    }

    #[test]
    fn output_overflow_is_a_typed_error() {
        let error =
            wait_for_child(spawn("yes x"), Some(5_000)).expect_err("output must be bounded");
        assert!(matches!(
            error,
            SandboxError::OutputLimitExceeded {
                limit_bytes: OUTPUT_CAPTURE_LIMIT_BYTES,
                ..
            }
        ));
    }

    #[test]
    fn timeout_kills_the_grandchild_process_group() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sentinel = temp.path().join("survived");
        let command = format!(
            "(sleep 0.4; printf survived > {}) & sleep 5",
            shell_quote(&sentinel.to_string_lossy())
        );
        let error = wait_for_child(spawn(&command), Some(100)).expect_err("must time out");
        assert!(matches!(error, SandboxError::Timeout { ms: 100 }));
        std::thread::sleep(Duration::from_millis(600));
        assert!(!sentinel.exists(), "grandchild survived its process group");
    }

    #[test]
    fn deadline_bounds_output_drain_when_an_unrelated_writer_remains_open() {
        let (reader, writer) = UnixStream::pair().expect("output pipe fixture");
        let held_writer = writer.try_clone().expect("hold another output writer");
        let holder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(750));
            drop(held_writer);
        });
        let mut command = shell_command("echo harmless-output");
        configure_process_group(&mut command);
        command
            .stdout(Stdio::from(OwnedFd::from(writer)))
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn harmless output child");
        drop(command);
        child.stdout = Some(std::process::ChildStdout::from(OwnedFd::from(reader)));

        let started = std::time::Instant::now();
        let result = wait_for_child(child, Some(100));
        let elapsed = started.elapsed();
        holder.join().expect("release unrelated writer");

        assert!(matches!(result, Err(SandboxError::Timeout { ms: 100 })));
        assert!(
            elapsed < Duration::from_millis(500),
            "the 100ms deadline must bound output drain even without EOF: {elapsed:?}"
        );
    }

    #[test]
    fn inherited_descriptor_child_observer() {
        let Ok(fd) = std::env::var("AGENT_GUARD_TEST_INHERITED_FD") else {
            return;
        };
        let fd = fd.parse::<i32>().unwrap();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // Test-only observer: never reads or writes through the candidate fd.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == 0 {
            let stat = unsafe { stat.assume_init() };
            let device = std::env::var("AGENT_GUARD_TEST_INHERITED_DEVICE").unwrap();
            let inode = std::env::var("AGENT_GUARD_TEST_INHERITED_INODE").unwrap();
            assert_ne!(
                (stat.st_dev.to_string(), stat.st_ino.to_string()),
                (device, inode),
                "child retained the fixture file's authority"
            );
        } else {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        }
    }

    #[test]
    fn inherited_non_stdio_descriptors_are_closed_at_exec() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sentinel = temp.path().join("descriptor-leak");
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&sentinel)
            .expect("open sentinel");
        // F_DUPFD deliberately creates a descriptor without FD_CLOEXEC.
        // SAFETY: `file` is open and remains alive through child spawning.
        let inherited = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 9) };
        assert!(
            inherited >= 0,
            "duplicate inherited fd: {}",
            std::io::Error::last_os_error()
        );

        let metadata = file.metadata().unwrap();
        for enforce_hygiene in [false, true] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "process::tests::inherited_descriptor_child_observer",
                ])
                .env("AGENT_GUARD_TEST_INHERITED_FD", inherited.to_string())
                .env(
                    "AGENT_GUARD_TEST_INHERITED_DEVICE",
                    metadata.dev().to_string(),
                )
                .env(
                    "AGENT_GUARD_TEST_INHERITED_INODE",
                    metadata.ino().to_string(),
                )
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if enforce_hygiene {
                configure_process_group(&mut command);
            } else {
                // Negative control: identical fork/exec path, with no hygiene.
                // SAFETY: the test-only pre-exec closure does no work.
                use std::os::unix::process::CommandExt;
                unsafe {
                    command.pre_exec(|| Ok(()));
                }
            }
            let output = wait_for_child(command.spawn().unwrap(), Some(5_000))
                .expect("capture descriptor observer");
            // The negative control proves that this fixture really was inheritable.
            // The hygienic case must remove that exact file authority, independently
            // of whether a runtime reuses the descriptor number for something else.
            assert_eq!(
                output.status.success(),
                enforce_hygiene,
                "descriptor observer (hygiene={enforce_hygiene}): {} {}",
                output.stdout,
                output.stderr
            );
        }
        // SAFETY: this test owns the descriptor returned by F_DUPFD.
        unsafe {
            libc::close(inherited);
        }

        assert_eq!(
            std::fs::read_to_string(&sentinel).expect("read sentinel"),
            ""
        );
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
