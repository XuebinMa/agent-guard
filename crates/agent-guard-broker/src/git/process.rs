use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::GitError;
use process_wrap::std::{ChildWrapper, CommandWrap};

pub(super) const DEFAULT_GIT_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
pub(super) struct Deadline {
    end: Instant,
    timeout: Duration,
}

impl Deadline {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            end: Instant::now() + timeout,
            timeout,
        }
    }

    pub(super) fn check(self, label: &str, started: bool) -> Result<(), GitError> {
        if Instant::now() >= self.end {
            Err(GitError::TimedOut {
                command: label.to_string(),
                timeout_ms: self.timeout.as_millis() as u64,
                started,
            })
        } else {
            Ok(())
        }
    }
}

pub(super) fn run(
    command: Command,
    input: Option<&[u8]>,
    deadline: Deadline,
    label: &str,
) -> Result<Output, GitError> {
    run_with_limit(command, input, deadline, label, MAX_OUTPUT_BYTES)
}

fn run_with_limit(
    mut command: Command,
    input: Option<&[u8]>,
    deadline: Deadline,
    label: &str,
    limit: u64,
) -> Result<Output, GitError> {
    deadline.check(label, false)?;
    if let Some(input) = input {
        let mut file = tempfile::tempfile()?;
        file.write_all(input)?;
        file.seek(SeekFrom::Start(0))?;
        command.stdin(Stdio::from(file));
    } else {
        command.stdin(Stdio::null());
    }
    // Regular files avoid pipe backpressure and EOF waits on inherited writers.
    // Size polling/read caps bound capture, not instantaneous disk allocation.
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    command.stdout(Stdio::from(stdout.try_clone()?));
    command.stderr(Stdio::from(stderr.try_clone()?));
    let mut wrapped = CommandWrap::from(command);
    #[cfg(unix)]
    wrapped.wrap(process_wrap::std::ProcessGroup::leader());
    #[cfg(windows)]
    wrapped.wrap(process_wrap::std::JobObject);
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "bounded broker processes require Unix groups or Windows jobs",
    )
    .into());

    deadline.check(label, false)?;
    let mut child = ManagedChild {
        child: wrapped.spawn()?,
        finished: false,
    };
    let result = loop {
        if let Err(error) = deadline.check(label, true) {
            break Err(error);
        }
        match output_size(&stdout, &stderr, limit, label) {
            Ok(()) => {}
            Err(error) => break Err(error),
        }
        match child.child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(error) => break Err(error.into()),
        }
        std::thread::sleep(
            POLL_INTERVAL.min(deadline.end.saturating_duration_since(Instant::now())),
        );
    };
    child.finish(label)?;
    let status = result?;
    output_size(&stdout, &stderr, limit, label)?;
    Ok(Output {
        status,
        stdout: read_output(&mut stdout, limit, label)?,
        stderr: read_output(&mut stderr, limit, label)?,
    })
}

fn output_size(stdout: &File, stderr: &File, limit: u64, label: &str) -> Result<(), GitError> {
    if stdout.metadata()?.len() > limit || stderr.metadata()?.len() > limit {
        return Err(GitError::OutputLimit {
            command: label.to_string(),
            limit_bytes: limit,
        });
    }
    Ok(())
}

fn read_output(file: &mut File, limit: u64, label: &str) -> Result<Vec<u8>, GitError> {
    file.seek(SeekFrom::Start(0))?;
    let mut body = Vec::new();
    file.take(limit + 1).read_to_end(&mut body)?;
    if body.len() as u64 > limit {
        return Err(GitError::OutputLimit {
            command: label.to_string(),
            limit_bytes: limit,
        });
    }
    Ok(body)
}

struct ManagedChild {
    child: Box<dyn ChildWrapper>,
    finished: bool,
}

impl ManagedChild {
    fn finish(&mut self, label: &str) -> Result<(), GitError> {
        let failed = |detail| GitError::CleanupFailed {
            command: label.to_string(),
            detail,
        };
        if let Err(error) = self.child.start_kill() {
            #[cfg(unix)]
            let already_gone = error.raw_os_error() == Some(libc::ESRCH);
            #[cfg(not(unix))]
            let already_gone = false;
            if !already_gone {
                return Err(failed(error.to_string()));
            }
        }
        let until = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.finished = true;
                    return Ok(());
                }
                Ok(None) if Instant::now() < until => std::thread::sleep(POLL_INTERVAL),
                Ok(None) => {
                    return Err(failed(
                        "managed leader could not be reaped within two seconds".into(),
                    ))
                }
                Err(error) => return Err(failed(error.to_string())),
            }
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.start_kill();
            let _ = self.child.try_wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const SCENARIO: &str = "AGENT_GUARD_OWNED_PROCESS_FIXTURE";

    fn fixture(scenario: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "git::process::tests::fixture_child",
            "--nocapture",
        ]);
        command.env(SCENARIO, scenario);
        command
    }

    #[test]
    fn fixture_child() {
        let Ok(scenario) = std::env::var(SCENARIO) else {
            return;
        };
        match scenario.as_str() {
            "sleep" => std::thread::sleep(Duration::from_millis(750)),
            "descendant" => {
                let mut child = fixture("marker").spawn().unwrap();
                std::thread::sleep(Duration::from_millis(1500));
                child.wait().unwrap();
            }
            "exited-parent" => {
                let mut child = fixture("marker").spawn().unwrap();
                let marker = std::env::var_os("AGENT_GUARD_OWNED_MARKER").unwrap();
                let until = Instant::now() + Duration::from_secs(1);
                while !Path::new(&marker).with_extension("started").exists()
                    && Instant::now() < until
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if Path::new(&marker).with_extension("started").exists() {
                    std::process::exit(0);
                }
                child.wait().unwrap();
                panic!("owned helper did not start");
            }
            "nonzero" => {
                println!("safe-nonzero-output");
                std::process::exit(7);
            }
            "marker" => {
                let marker = std::env::var_os("AGENT_GUARD_OWNED_MARKER").unwrap();
                std::fs::write(Path::new(&marker).with_extension("started"), b"started").unwrap();
                std::thread::sleep(Duration::from_millis(1000));
                std::fs::write(marker, b"finished").unwrap();
            }
            "large" => {
                std::io::stdout()
                    .write_all(&vec![b'a'; 128 * 1024])
                    .unwrap();
                std::io::stderr()
                    .write_all(&vec![b'b'; 128 * 1024])
                    .unwrap();
                // Keep this finite fixture alive so the test specifically
                // exercises output-limit termination, not an exit/kill race.
                std::thread::sleep(Duration::from_millis(250));
            }
            "output" => {
                println!("safe-output");
                eprintln!("safe-error");
            }
            "input" => {
                let text = std::io::read_to_string(std::io::stdin()).unwrap();
                println!("safe-input:{text}");
            }
            other => panic!("unknown owned fixture {other}"),
        }
    }

    #[test]
    fn a_stalled_owned_process_returns_a_timeout_instead_of_waiting() {
        let started = Instant::now();
        let result = run(
            fixture("sleep"),
            None,
            Deadline::new(Duration::from_millis(75)),
            "fixture",
        );
        assert!(
            matches!(result, Err(GitError::TimedOut { started: true, .. })),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn timeout_terminates_the_owned_descendant_too() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("finished");
        let mut command = fixture("descendant");
        command.env("AGENT_GUARD_OWNED_MARKER", &marker);
        let result = run(
            command,
            None,
            Deadline::new(Duration::from_millis(300)),
            "fixture",
        );
        assert!(
            marker.with_extension("started").exists(),
            "the descendant fixture must actually start"
        );
        std::thread::sleep(Duration::from_millis(1100));
        assert!(result.is_err(), "a deadline is not a successful execution");
        assert!(
            !Path::new(&marker).exists(),
            "the managed helper survived the timeout"
        );
    }

    #[test]
    fn ordinary_output_and_explicit_input_are_preserved() {
        let output = run(
            fixture("output"),
            None,
            Deadline::new(Duration::from_secs(2)),
            "fixture",
        )
        .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("safe-output"));
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("safe-error"));
        let output = run(
            fixture("input"),
            Some(b"public-fixture"),
            Deadline::new(Duration::from_secs(2)),
            "fixture",
        )
        .unwrap();
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("safe-input:public-fixture"));
        let output = run(
            fixture("input"),
            None,
            Deadline::new(Duration::from_secs(2)),
            "fixture",
        )
        .unwrap();
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("safe-input:\n"));
    }

    #[test]
    fn an_expired_shared_budget_cannot_spawn_another_child() {
        let deadline = Deadline::new(Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(30));
        let result = run(fixture("output"), None, deadline, "fixture");
        assert!(matches!(
            result,
            Err(GitError::TimedOut { started: false, .. })
        ));
    }

    #[test]
    fn an_exited_parent_does_not_leave_its_inherited_output_writer_running() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("finished");
        let mut command = fixture("exited-parent");
        command.env("AGENT_GUARD_OWNED_MARKER", &marker);
        let output = run(
            command,
            None,
            Deadline::new(Duration::from_secs(2)),
            "fixture",
        )
        .unwrap();
        assert!(output.status.success());
        assert!(marker.with_extension("started").exists());
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            !marker.exists(),
            "the helper inherited output and outlived its managed group"
        );
    }

    #[test]
    fn a_completed_nonzero_process_keeps_its_exit_code_and_output() {
        let output = run(
            fixture("nonzero"),
            None,
            Deadline::new(Duration::from_secs(2)),
            "fixture",
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("safe-nonzero-output"));
    }

    #[test]
    fn excessive_output_is_refused_instead_of_returning_a_truncated_answer() {
        let result = run_with_limit(
            fixture("large"),
            None,
            Deadline::new(Duration::from_secs(2)),
            "fixture",
            64 * 1024,
        );
        assert!(
            matches!(result, Err(GitError::OutputLimit { .. })),
            "{result:?}"
        );
    }
}
