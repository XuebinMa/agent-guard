//! Shared child-process lifecycle for Unix sandbox backends and the noop
//! runner.
//!
//! Pipes are drained concurrently with a fixed retention limit. On Unix each
//! command starts a new session, allowing timeout/resource cleanup to target
//! the complete process group instead of only the shell process.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{SandboxError, OUTPUT_CAPTURE_LIMIT_BYTES};

const STDOUT_LIMIT_BIT: u8 = 1;
const STDERR_LIMIT_BIT: u8 = 2;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug)]
pub(crate) struct CapturedChild {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) status: ExitStatus,
}

/// Arrange for the spawned program and descendants to live in a fresh Unix
/// session/process group. Multiple `pre_exec` callbacks are supported, so a
/// backend may add its seccomp/Landlock setup after this callback.
#[cfg(unix)]
pub(crate) fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: `setsid` is async-signal-safe and touches no parent memory. A
    // failure aborts spawning instead of running without tree ownership.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(not(unix))]
pub(crate) fn configure_process_group(_command: &mut Command) {}

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

    let limit_flags = Arc::new(AtomicU8::new(0));
    let stdout_flags = Arc::clone(&limit_flags);
    let stderr_flags = Arc::clone(&limit_flags);
    let stdout_thread = thread::spawn(move || read_bounded(stdout, STDOUT_LIMIT_BIT, stdout_flags));
    let stderr_thread = thread::spawn(move || read_bounded(stderr, STDERR_LIMIT_BIT, stderr_flags));

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
) -> io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = reader.read(&mut buffer)?;
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

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
