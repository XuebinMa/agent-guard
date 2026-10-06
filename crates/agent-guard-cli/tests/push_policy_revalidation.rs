//! The policy shown at preview must still authorize the push after confirmation.
//! All repositories, configuration, grants, and writes stay in one temp fixture.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const ALLOW_POLICY: &str = "version: 1\ndefault_mode: workspace_write\naudit:\n  enabled: false\nanomaly:\n  enabled: false\n";
const DENY_POLICY: &str = "version: 1\ndefault_mode: workspace_write\ntools:\n  bash:\n    deny:\n      - prefix: 'git push'\naudit:\n  enabled: false\nanomaly:\n  enabled: false\n";

struct Fixture {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    remote: PathBuf,
    policy: PathBuf,
    config: PathBuf,
    grants: PathBuf,
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .current_dir(repo)
        .output()
        .expect("Git starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let remote = dir.path().join("remote.git");
        let policy = dir.path().join("policy.yaml");
        let config = dir.path().join("broker.gitconfig");
        let grants = dir.path().join("grants");
        std::fs::create_dir(&repo).unwrap();
        std::fs::write(&policy, ALLOW_POLICY).unwrap();
        std::fs::write(&config, "").unwrap();
        git(
            dir.path(),
            &["init", "--bare", "-b", "main", remote.to_str().unwrap()],
        );
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "Local fixture"]);
        git(&repo, &["config", "user.email", "fixture@example.invalid"]);
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        std::fs::write(repo.join("fixture.txt"), "initial").unwrap();
        git(&repo, &["add", "fixture.txt"]);
        git(&repo, &["commit", "-m", "initial local fixture"]);
        git(&repo, &["push", "origin", "main"]);
        std::fs::write(repo.join("fixture.txt"), "pending").unwrap();
        git(&repo, &["commit", "-am", "pending local fixture"]);
        Self {
            _dir: dir,
            repo,
            remote,
            policy,
            config,
            grants,
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_pending_push(change_policy: impl FnOnce(&Path), should_push: bool) {
    let f = Fixture::new();
    let before = git(&f.remote, &["rev-parse", "refs/heads/main"]);
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_agent-guard"))
            .arg("push")
            .arg("--repo")
            .arg(&f.repo)
            .arg("--policy")
            .arg(&f.policy)
            .arg("--git-config")
            .arg(&f.config)
            .arg("--grants")
            .arg(&f.grants)
            .args([
                "--remote",
                "origin",
                "--branch",
                "main",
                "--allow-local-file-remote",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = child.0.stdout.take().unwrap();
    let (ready, receive_ready) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut byte = [0];
        let mut signaled = false;
        while stdout.read(&mut byte).unwrap_or(0) == 1 {
            output.push(byte[0]);
            if !signaled && output.ends_with(b"Push this? [y/N] ") {
                let _ = ready.send(());
                signaled = true;
            }
        }
        String::from_utf8_lossy(&output).into_owned()
    });
    receive_ready
        .recv_timeout(Duration::from_secs(20))
        .expect("preview asks for confirmation");
    change_policy(&f.policy);
    child.0.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "broker must finish within the test deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = reader.join().unwrap();
    let after = git(&f.remote, &["rev-parse", "refs/heads/main"]);
    assert_eq!(status.success(), should_push, "{output}");
    assert_eq!(
        after != before,
        should_push,
        "only an unchanged approved policy may update the local remote"
    );
}

#[test]
fn a_policy_tightened_during_confirmation_refuses_the_push() {
    run_pending_push(|path| std::fs::write(path, DENY_POLICY).unwrap(), false);
}

#[test]
fn a_policy_removed_during_confirmation_refuses_the_push() {
    run_pending_push(|path| std::fs::remove_file(path).unwrap(), false);
}

#[test]
fn an_unchanged_policy_allows_the_confirmed_local_push() {
    run_pending_push(|_| {}, true);
}
