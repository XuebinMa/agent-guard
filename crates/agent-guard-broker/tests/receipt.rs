//! What the broker witnessed, in a form someone else can check.
//!
//! A receipt is emitted for every attempt, successful or refused. The one
//! thing it must never do is be absent: "no receipt" would be read as "no
//! push was attempted", and an operator who reaches that conclusion because
//! no signing key was configured has been misled by their own tooling.

use std::path::Path;
use std::process::Command;

use agent_guard_broker::{
    execute_push_with_receipt, issue_grant, resolve_push_transaction, PushAttempt, Witness,
};
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

struct Fixture {
    _dir: tempfile::TempDir,
    work: std::path::PathBuf,
    grants: std::path::PathBuf,
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
        grants,
    }
}

fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

/// A witnessed push produces a receipt naming what actually landed.
#[test]
fn a_successful_push_is_witnessed_and_signed() {
    let f = fixture();
    let pushed = commit(&f.work, "second");
    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    let key = signing_key();
    let receipt = execute_push_with_receipt(
        &f.work,
        &f.grants,
        &grant,
        "policy-1",
        Utc::now(),
        Some(&key),
    );

    assert_eq!(receipt.attempt, PushAttempt::Pushed);
    assert_eq!(
        receipt.transaction.as_ref().expect("resolved").local_oid,
        pushed
    );
    assert_eq!(receipt.grant_id.as_deref(), Some(grant.as_str()));

    match &receipt.witness {
        Witness::Signed { .. } => {}
        other => panic!("a guard-executed push must be signed when a key exists: {other:?}"),
    }
    assert!(receipt.verify(&key.verifying_key()));
}

/// No key is a weaker receipt, not a missing one. Absence would read as
/// "nothing was attempted".
#[test]
fn a_push_without_a_signing_key_still_produces_a_receipt() {
    let f = fixture();
    let pushed = commit(&f.work, "second");
    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    let receipt =
        execute_push_with_receipt(&f.work, &f.grants, &grant, "policy-1", Utc::now(), None);

    assert_eq!(receipt.attempt, PushAttempt::Pushed);
    assert_eq!(
        receipt.transaction.as_ref().expect("resolved").local_oid,
        pushed
    );
    assert_eq!(
        receipt.witness,
        Witness::Unsigned,
        "an unsigned witness must say so rather than be absent"
    );
    assert!(
        !receipt.verify(&signing_key().verifying_key()),
        "an unsigned receipt must never verify"
    );
}

/// A refusal is a receipt too. The most interesting thing a broker does is
/// decline, and a record that only covers successes cannot show that.
#[test]
fn a_refused_push_is_recorded_with_its_reason() {
    let f = fixture();
    commit(&f.work, "second");
    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");

    // The agent commits again: the approved transaction no longer describes
    // this repository.
    commit(&f.work, "after approval");

    let key = signing_key();
    let receipt = execute_push_with_receipt(
        &f.work,
        &f.grants,
        &grant,
        "policy-1",
        Utc::now(),
        Some(&key),
    );

    match &receipt.attempt {
        PushAttempt::Refused { reason } => {
            assert!(!reason.is_empty(), "a refusal must say why");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        receipt.verify(&key.verifying_key()),
        "a refusal is witnessed too and is signed like any other outcome"
    );
}

/// The signature covers the outcome. Rewriting a refusal into a success must
/// not survive verification.
#[test]
fn editing_the_outcome_breaks_the_signature() {
    let f = fixture();
    commit(&f.work, "second");
    let tx = resolve_push_transaction(&f.work, "origin", "main").expect("resolves");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("issues");
    commit(&f.work, "after approval");

    let key = signing_key();
    let mut receipt = execute_push_with_receipt(
        &f.work,
        &f.grants,
        &grant,
        "policy-1",
        Utc::now(),
        Some(&key),
    );
    assert!(receipt.verify(&key.verifying_key()));

    receipt.attempt = PushAttempt::Pushed;

    assert!(
        !receipt.verify(&key.verifying_key()),
        "a receipt edited after signing must not verify"
    );
}
