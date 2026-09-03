//! One-use authorization.
//!
//! A grant is the answer to "which push did the human approve?". It is bound
//! to one resolved transaction, it expires, and it can be spent once. The
//! last property is the one that needs care: a check that reads the grant,
//! decides it is unspent, and then marks it spent has a window between the
//! read and the write in which a second caller can do the same.

use std::path::Path;
use std::sync::{Arc, Barrier};

use agent_guard_broker::{issue_grant, spend_grant, GrantError, PushTransaction, RefUpdateKind};
use chrono::{Duration, Utc};

fn transaction(local: &str) -> PushTransaction {
    PushTransaction {
        remote: "origin".to_string(),
        remote_url: "https://example.invalid/repo.git".to_string(),
        branch: "main".to_string(),
        local_oid: local.to_string(),
        remote_oid: Some("aaaa".to_string()),
        kind: RefUpdateKind::FastForward,
        added_commits: Some(vec![local.to_string()]),
    }
}

fn issue(dir: &Path, tx: &PushTransaction, ttl: Duration) -> String {
    issue_grant(dir, tx, "policy-hash-1", "human@example.invalid", ttl).expect("issues")
}

/// The ordinary path: a grant authorizes the transaction it was issued for.
#[test]
fn a_grant_authorizes_the_transaction_it_was_issued_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tx = transaction("bbbb");
    let id = issue(dir.path(), &tx, Duration::minutes(5));

    let grant = spend_grant(dir.path(), &id, &tx, "policy-hash-1", Utc::now()).expect("spends");

    assert_eq!(grant.transaction_digest, tx.digest());
    assert_eq!(grant.actor, "human@example.invalid");
}

/// Spending is the whole point. A second attempt has nothing to spend.
#[test]
fn a_grant_cannot_be_spent_twice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tx = transaction("bbbb");
    let id = issue(dir.path(), &tx, Duration::minutes(5));

    spend_grant(dir.path(), &id, &tx, "policy-hash-1", Utc::now()).expect("first spend");
    let second = spend_grant(dir.path(), &id, &tx, "policy-hash-1", Utc::now());

    assert!(
        matches!(second, Err(GrantError::NotFound { .. })),
        "a spent grant must not be spendable again, got {second:?}"
    );
}

/// The property a read-then-write check cannot provide. Many callers race for
/// one grant; exactly one may win.
#[test]
fn concurrent_spenders_produce_exactly_one_winner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tx = transaction("bbbb");
    let id = issue(dir.path(), &tx, Duration::minutes(5));

    let racers = 16;
    let barrier = Arc::new(Barrier::new(racers));
    let path = dir.path().to_path_buf();

    let handles: Vec<_> = (0..racers)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            let tx = tx.clone();
            let id = id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                spend_grant(&path, &id, &tx, "policy-hash-1", Utc::now()).is_ok()
            })
        })
        .collect();

    let winners = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .filter(|won| *won)
        .count();

    assert_eq!(winners, 1, "exactly one spender may win, {winners} did");
}

/// A grant is bound to one transaction. A different effect is not what the
/// human looked at, whatever the command line says.
#[test]
fn a_grant_does_not_authorize_a_different_transaction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let approved = transaction("bbbb");
    let id = issue(dir.path(), &approved, Duration::minutes(5));

    let different = transaction("cccc");
    let result = spend_grant(dir.path(), &id, &different, "policy-hash-1", Utc::now());

    assert!(
        matches!(result, Err(GrantError::TransactionMismatch { .. })),
        "got {result:?}"
    );
}

/// Policy can change between issuing and spending. A grant issued under one
/// policy does not carry over to another.
#[test]
fn a_grant_does_not_survive_a_policy_change() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tx = transaction("bbbb");
    let id = issue(dir.path(), &tx, Duration::minutes(5));

    let result = spend_grant(dir.path(), &id, &tx, "policy-hash-2", Utc::now());

    assert!(
        matches!(result, Err(GrantError::PolicyChanged { .. })),
        "got {result:?}"
    );
}

/// Expiry is checked against the grant's own recorded deadline, so a reader
/// holding the spent grant can tell whether the refusal was correct.
#[test]
fn an_expired_grant_is_refused_and_says_what_it_expired_against() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tx = transaction("bbbb");
    let id = issue(dir.path(), &tx, Duration::seconds(1));

    let later = Utc::now() + Duration::minutes(1);
    let result = spend_grant(dir.path(), &id, &tx, "policy-hash-1", later);

    match result {
        Err(GrantError::Expired { expires_at, at }) => {
            assert!(
                at > expires_at,
                "the refusal must be checkable: {at} vs {expires_at}"
            );
        }
        other => panic!("expected an expiry refusal, got {other:?}"),
    }
}

/// A grant that fails validation is still spent. The only reasons validation
/// fails are that the effect changed or someone is probing, and both require
/// a fresh human decision, so nothing is lost by burning it — while leaving
/// it spendable would allow repeated attempts against one approval.
#[test]
fn a_rejected_presentation_still_consumes_the_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let approved = transaction("bbbb");
    let id = issue(dir.path(), &approved, Duration::minutes(5));

    let _ = spend_grant(
        dir.path(),
        &id,
        &transaction("cccc"),
        "policy-hash-1",
        Utc::now(),
    );

    let retry = spend_grant(dir.path(), &id, &approved, "policy-hash-1", Utc::now());
    assert!(
        matches!(retry, Err(GrantError::NotFound { .. })),
        "a presented grant is spent even when refused, got {retry:?}"
    );
}

/// Grant identifiers come from the issuer, and a caller cannot reach outside
/// the grant directory by supplying a path.
#[test]
fn a_grant_id_cannot_escape_the_grant_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().parent().expect("parent").join("outside.json");
    std::fs::write(&outside, "{}").expect("write");

    let tx = transaction("bbbb");
    let result = spend_grant(dir.path(), "../outside", &tx, "policy-hash-1", Utc::now());

    assert!(
        matches!(result, Err(GrantError::InvalidId { .. })),
        "got {result:?}"
    );
    assert!(
        outside.exists(),
        "the file outside the directory must be untouched"
    );
}
