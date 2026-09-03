//! Executing exactly the approved push, and nothing else.
//!
//! The window between deciding and acting is where both sides move, so the
//! execution path re-resolves, spends the grant against what it just
//! resolved — which makes authorization and drift detection the same check —
//! and then pushes in a form that pins both ends: the approved object rather
//! than whatever the branch now points at, and a lease on the remote object
//! the human was shown.

use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard_broker::{execute_push, issue_grant, resolve_push_transaction, ExecuteError};
use chrono::{Duration, Utc};

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit(repo: &Path, message: &str) -> String {
    std::fs::write(repo.join("file.txt"), message).expect("write");
    git(repo, &["add", "."]);
    git(repo, &["commit", "-m", message]);
    git(repo, &["rev-parse", "HEAD"])
}

fn remote_head(remote: &Path) -> String {
    git(remote, &["rev-parse", "refs/heads/main"])
}

struct Fixture {
    _dir: tempfile::TempDir,
    work: PathBuf,
    remote: PathBuf,
    grants: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let remote = dir.path().join("remote.git");
    let work = dir.path().join("work");
    let grants = dir.path().join("grants");
    std::fs::create_dir_all(&work).expect("mkdir");

    Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&remote)
        .output()
        .expect("git init --bare");

    git(&work, &["init", "-b", "main"]);
    git(&work, &["config", "user.email", "test@example.invalid"]);
    git(&work, &["config", "user.name", "Test"]);
    git(
        &work,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    commit(&work, "first");
    git(&work, &["push", "origin", "main"]);

    Fixture {
        _dir: dir,
        work,
        remote,
        grants,
    }
}

/// The ordinary path: what was approved is what lands.
#[test]
fn an_approved_push_lands_exactly_that_object() {
    let f = fixture();
    let approved_oid = commit(&f.work, "second");

    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    let outcome = execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now()).expect("pushes");

    assert_eq!(outcome.pushed_oid, approved_oid);
    assert_eq!(remote_head(&f.remote), approved_oid);
}

/// The agent commits again between approval and execution. The push must
/// carry the approved object, and the later commit must not reach the remote.
#[test]
fn a_commit_made_after_approval_does_not_ride_along() {
    let f = fixture();
    let approved_oid = commit(&f.work, "second");
    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    let sneaked = commit(&f.work, "added after approval");
    assert_ne!(sneaked, approved_oid);

    let result = execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now());

    assert!(
        matches!(result, Err(ExecuteError::Drift { .. })),
        "a moved local branch must be refused, got {result:?}"
    );
    assert_eq!(
        remote_head(&f.remote),
        git(&f.work, &["rev-parse", "HEAD~2"]),
        "the remote must still hold what it had before"
    );
}

/// Someone else advanced the remote after the human looked. Even a
/// fast-forward from there is a state nobody approved.
#[test]
fn a_remote_advanced_after_approval_is_refused() {
    let f = fixture();
    commit(&f.work, "second");
    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    let other = f.work.parent().expect("parent").join("other");
    Command::new("git")
        .args(["clone"])
        .arg(&f.remote)
        .arg(&other)
        .output()
        .expect("clone");
    git(&other, &["config", "user.email", "other@example.invalid"]);
    git(&other, &["config", "user.name", "Other"]);
    let theirs = commit(&other, "theirs");
    git(&other, &["push", "origin", "main"]);

    let result = execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now());

    assert!(result.is_err(), "got {result:?}");
    assert_eq!(
        remote_head(&f.remote),
        theirs,
        "the other party's commit must still be the remote tip"
    );
}

/// The first supported shape is an ordinary non-force push. Anything that
/// would discard history fails closed rather than being forced through.
#[test]
fn a_non_fast_forward_is_refused_before_any_push() {
    let f = fixture();
    commit(&f.work, "second");
    git(&f.work, &["push", "origin", "main"]);
    let shared = remote_head(&f.remote);

    git(&f.work, &["reset", "--hard", "HEAD~1"]);
    commit(&f.work, "rewritten");

    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    let result = execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now());

    assert!(
        matches!(result, Err(ExecuteError::UnsupportedShape { .. })),
        "got {result:?}"
    );
    assert_eq!(
        remote_head(&f.remote),
        shared,
        "nothing may have been pushed"
    );
}

/// A grant is spent by the first execution, successful or not.
#[test]
fn a_grant_cannot_drive_two_pushes() {
    let f = fixture();
    commit(&f.work, "second");
    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now()).expect("first push");
    let third = commit(&f.work, "third");

    let result = execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now());

    assert!(result.is_err(), "got {result:?}");
    assert_ne!(remote_head(&f.remote), third);
}
