//! I1 locks at the actual execution API, not just the grant store.
//! Synthetic records, local Git objects and a bounded loopback observer only.
#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration as Wait, Instant};

use agent_guard_broker::{
    issue_grant, BrokerGitOptions, ExecuteError, GrantError, PushBroker, PushTransaction,
    RefUpdateKind,
};
use chrono::{Duration, Utc};

fn git(repo: &Path, args: &[&str]) -> String {
    let mut child = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .current_dir(repo)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("trusted test PATH"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("local fixture Git starts");
    let deadline = Instant::now() + Wait::from_secs(20);
    while child.try_wait().expect("fixture wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("local Git fixture exceeded its deadline");
        }
        thread::sleep(Wait::from_millis(5));
    }
    let output = child.wait_with_output().expect("fixture output");
    assert!(
        output.status.success(),
        "{:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("fixture UTF-8")
        .trim()
        .to_string()
}

struct Observer {
    url: String,
    contacts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Observer {
    fn new() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local observer");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("observer address");
        let contacts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counted = Arc::clone(&contacts);
        let ended = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Wait::from_secs(10);
            while !ended.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        drop(stream); // No TLS/authentication or payload handling.
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Wait::from_millis(2));
                    }
                    Err(error) => panic!("local observer: {error}"),
                }
            }
        });
        // Positive control: reachable listener, rather than a disconnected test.
        drop(TcpStream::connect_timeout(&address, Wait::from_secs(1)).expect("reachable observer"));
        let deadline = Instant::now() + Wait::from_secs(1);
        while contacts.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            thread::sleep(Wait::from_millis(2));
        }
        assert_eq!(contacts.load(Ordering::SeqCst), 1);
        contacts.store(0, Ordering::SeqCst);
        Self {
            url: format!("https://{address}/repo.git"),
            contacts,
            stop,
            worker: Some(worker),
        }
    }

    fn assert_no_execution_contact(&self) {
        thread::sleep(Wait::from_millis(10));
        assert_eq!(
            self.contacts.load(Ordering::SeqCst),
            0,
            "unauthorized execution contacted the fixture"
        );
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .expect("observer worker")
            .join()
            .expect("observer joins");
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    repo: PathBuf,
    grants: PathBuf,
    tx: PushTransaction,
    observer: Observer,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("owned fixture");
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).expect("fixture directory");
    git(&repo, &["init", "-b", "main"]);
    git(&repo, &["config", "user.name", "Local Fixture"]);
    git(&repo, &["config", "user.email", "fixture@example.invalid"]);
    std::fs::write(repo.join("fixture.txt"), "harmless lifecycle fixture\n").expect("fixture data");
    git(&repo, &["add", "fixture.txt"]);
    git(&repo, &["commit", "-m", "fixture"]);
    let oid = git(&repo, &["rev-parse", "HEAD"]);
    let observer = Observer::new();
    git(&repo, &["remote", "add", "origin", &observer.url]);
    let tx = PushTransaction {
        remote: "origin".into(),
        remote_url: observer.url.clone(),
        branch: "main".into(),
        local_oid: oid.clone(),
        remote_oid: None,
        kind: RefUpdateKind::Create,
        added_commits: Some(vec![oid]),
    };
    Fixture {
        grants: root.path().join("grants"),
        _root: root,
        repo,
        tx,
        observer,
    }
}

fn issued(f: &Fixture) -> String {
    issue_grant(
        &f.grants,
        &f.tx,
        "fixture-policy",
        "host-fixture",
        Duration::minutes(1),
    )
    .expect("record")
}

#[test]
fn missing_record_is_refused_at_execution_without_remote_contact() {
    let f = fixture();
    let result = PushBroker::default().execute_push(
        &f.repo,
        &f.grants,
        "missing",
        "fixture-policy",
        Utc::now(),
    );
    assert!(matches!(
        result,
        Err(ExecuteError::Unauthorized(GrantError::NotFound { .. }))
    ));
    f.observer.assert_no_execution_contact();
}

#[test]
fn expired_record_is_refused_at_execution_without_remote_contact() {
    let f = fixture();
    let id = issued(&f);
    let result = PushBroker::default().execute_push(
        &f.repo,
        &f.grants,
        &id,
        "fixture-policy",
        Utc::now() + Duration::minutes(2),
    );
    assert!(matches!(
        result,
        Err(ExecuteError::Unauthorized(GrantError::Expired { .. }))
    ));
    assert!(f.grants.join("spent").join(format!("{id}.json")).is_file());
    f.observer.assert_no_execution_contact();
}

#[test]
fn inconsistent_record_is_refused_at_execution_without_remote_contact() {
    let f = fixture();
    let id = issued(&f);
    let path = f.grants.join(format!("{id}.json"));
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("fixture record")).expect("JSON");
    record["transaction_digest"] = serde_json::Value::String("inconsistent-fixture".into());
    std::fs::write(path, serde_json::to_vec(&record).expect("fixture JSON"))
        .expect("replace synthetic record");
    let result =
        PushBroker::default().execute_push(&f.repo, &f.grants, &id, "fixture-policy", Utc::now());
    assert!(matches!(
        result,
        Err(ExecuteError::Unauthorized(GrantError::Corrupt { .. }))
    ));
    f.observer.assert_no_execution_contact();
}

#[test]
fn consumed_record_cannot_reenter_execution_or_contact_a_remote() {
    let f = fixture();
    let id = issued(&f);
    let broker = PushBroker::default();
    // A policy change consumes this one-use record without any Git operation.
    assert!(matches!(
        broker.execute_push(&f.repo, &f.grants, &id, "new-fixture-policy", Utc::now()),
        Err(ExecuteError::Unauthorized(GrantError::PolicyChanged { .. }))
    ));
    assert!(matches!(
        broker.execute_push(&f.repo, &f.grants, &id, "fixture-policy", Utc::now()),
        Err(ExecuteError::Unauthorized(GrantError::NotFound { .. }))
    ));
    f.observer.assert_no_execution_contact();
}

#[test]
fn valid_local_execution_updates_exactly_once_and_replay_is_refused() {
    let f = fixture();
    let remote = f._root.path().join("local.git");
    git(
        f._root.path(),
        &[
            "init",
            "--bare",
            "-b",
            "main",
            remote.to_str().expect("fixture path"),
        ],
    );
    git(
        &f.repo,
        &[
            "remote",
            "set-url",
            "origin",
            remote.to_str().expect("fixture path"),
        ],
    );
    let broker = PushBroker::new(BrokerGitOptions {
        trusted_config: None,
        allow_local_file_remote: true,
    });
    let tx = broker
        .resolve_push_transaction(&f.repo, "origin", "main")
        .expect("local preview");
    let id = issue_grant(
        &f.grants,
        &tx,
        "fixture-policy",
        "host-fixture",
        Duration::minutes(1),
    )
    .expect("record");
    let outcome = broker
        .execute_push(&f.repo, &f.grants, &id, "fixture-policy", Utc::now())
        .expect("local push");
    assert_eq!(outcome.pushed_oid, tx.local_oid);
    assert_eq!(
        git(&remote, &["rev-parse", "refs/heads/main"]),
        tx.local_oid
    );
    assert!(matches!(
        broker.execute_push(&f.repo, &f.grants, &id, "fixture-policy", Utc::now()),
        Err(ExecuteError::Unauthorized(GrantError::NotFound { .. }))
    ));
    assert_eq!(
        git(&remote, &["rev-parse", "refs/heads/main"]),
        tx.local_oid
    );
    f.observer.assert_no_execution_contact();
}
