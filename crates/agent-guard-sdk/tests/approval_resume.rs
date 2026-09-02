//! S7-4 integration: `Guard::run_until_approved` blocking approval resume.
//!
//! A second thread plays the human running `agent-guard approve/deny`: it waits
//! for the pending request to appear in the ledger, then decides it. The main
//! thread blocks in `run_until_approved` and observes the resumed outcome.

use std::thread;
use std::time::Duration;

use agent_guard_sandbox::NoopSandbox;
use agent_guard_sdk::{
    ApprovalConfig, ApprovalLedger, ApprovalStatus, Context, DecisionCode, Guard, GuardInput,
    RuntimeOutcome, Tool, TrustLevel,
};

const ASK_POLICY: &str = r#"
version: 1
default_mode: workspace_write
tools:
  bash:
    mode: workspace_write
    ask:
      - prefix: "git push"
    deny:
      - prefix: "rm -rf /"
"#;

const DENY_PUSH_POLICY: &str = r#"
version: 1
default_mode: workspace_write
tools:
  bash:
    mode: workspace_write
    deny:
      - prefix: "git push"
"#;

fn guard() -> Guard {
    Guard::from_yaml(ASK_POLICY).expect("policy parses")
}

fn bash(command: &str) -> GuardInput {
    GuardInput {
        tool: Tool::Bash,
        payload: format!(r#"{{"command":"{command}"}}"#),
        context: Context {
            trust_level: TrustLevel::Trusted,
            ..Default::default()
        },
    }
}

fn config(ledger: &ApprovalLedger, timeout: Duration) -> ApprovalConfig {
    ApprovalConfig::new(ledger.clone())
        .with_poll_interval(Duration::from_millis(25))
        .with_timeout(timeout)
}

/// Block until a pending request appears, returning its id.
fn wait_for_pending(ledger: &ApprovalLedger) -> String {
    for _ in 0..400 {
        if let Some(record) = ledger
            .list_pending()
            .expect("list pending")
            .into_iter()
            .next()
        {
            return record.request_id;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("no pending approval request ever appeared");
}

#[test]
fn approved_request_executes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));

    let approver = {
        let ledger = ledger.clone();
        thread::spawn(move || {
            let id = wait_for_pending(&ledger);
            ledger
                .approve(&id, Some("tester".to_string()))
                .expect("approve");
        })
    };

    let outcome = guard()
        .run_until_approved(
            &bash("git push origin main"),
            &NoopSandbox,
            &config(&ledger, Duration::from_secs(10)),
        )
        .expect("no sandbox error");
    approver.join().expect("approver thread");

    assert!(
        matches!(outcome, RuntimeOutcome::Executed { .. }),
        "expected Executed, got {outcome:?}"
    );
}

#[test]
fn approval_is_revalidated_against_the_current_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));
    let guard = std::sync::Arc::new(guard());

    let runner = {
        let guard = guard.clone();
        let ledger = ledger.clone();
        thread::spawn(move || {
            guard.run_until_approved(
                &bash("git push origin main"),
                &NoopSandbox,
                &config(&ledger, Duration::from_secs(10)),
            )
        })
    };

    let request_id = wait_for_pending(&ledger);
    guard
        .reload_from_yaml(DENY_PUSH_POLICY)
        .expect("reload deny policy");
    ledger
        .approve(&request_id, Some("tester".to_string()))
        .expect("approve");

    let outcome = runner
        .join()
        .expect("runner thread")
        .expect("runtime result");
    match outcome {
        RuntimeOutcome::Denied { reason, .. } => {
            assert_eq!(reason.code(), DecisionCode::DeniedByRule);
        }
        other => panic!("policy reload must prevent execution, got {other:?}"),
    }
}

#[test]
fn approval_record_must_stay_bound_to_the_original_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger_path = dir.path().join("approvals.jsonl");
    let ledger = ApprovalLedger::open(&ledger_path);

    let runner = {
        let ledger = ledger.clone();
        thread::spawn(move || {
            guard().run_until_approved(
                &bash("git push origin main"),
                &NoopSandbox,
                &config(&ledger, Duration::from_secs(10)),
            )
        })
    };

    let request_id = wait_for_pending(&ledger);
    let contents = std::fs::read_to_string(&ledger_path).expect("read ledger");
    let mut event: serde_json::Value =
        serde_json::from_str(contents.lines().next().expect("created event"))
            .expect("parse created event");
    event["payload_hash"] = serde_json::Value::String("forged".to_string());
    std::fs::write(
        &ledger_path,
        format!("{}\n", serde_json::to_string(&event).expect("serialize")),
    )
    .expect("tamper ledger fixture");
    ledger
        .approve(&request_id, Some("tester".to_string()))
        .expect("approve");

    let outcome = runner
        .join()
        .expect("runner thread")
        .expect("runtime result");
    match outcome {
        RuntimeOutcome::Denied { reason, .. } => {
            assert_eq!(reason.code(), DecisionCode::ApprovalDenied);
        }
        other => panic!("tampered approval binding must deny, got {other:?}"),
    }
}

#[test]
fn denied_request_is_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));

    let denier = {
        let ledger = ledger.clone();
        thread::spawn(move || {
            let id = wait_for_pending(&ledger);
            ledger.deny(&id, Some("tester".to_string())).expect("deny");
        })
    };

    let outcome = guard()
        .run_until_approved(
            &bash("git push origin main"),
            &NoopSandbox,
            &config(&ledger, Duration::from_secs(10)),
        )
        .expect("no sandbox error");
    denier.join().expect("denier thread");

    match outcome {
        RuntimeOutcome::Denied { reason, .. } => {
            assert_eq!(reason.code(), DecisionCode::ApprovalDenied);
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn timeout_denies_and_marks_expired() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));

    // No approver thread: the request will time out.
    let outcome = guard()
        .run_until_approved(
            &bash("git push origin main"),
            &NoopSandbox,
            &config(&ledger, Duration::from_millis(150)),
        )
        .expect("no sandbox error");

    let request_id = match outcome {
        RuntimeOutcome::Denied {
            request_id, reason, ..
        } => {
            assert_eq!(reason.code(), DecisionCode::ApprovalDenied);
            request_id
        }
        other => panic!("expected Denied, got {other:?}"),
    };

    let record = ledger.get(&request_id).expect("get").expect("present");
    assert_eq!(record.status, ApprovalStatus::Expired);
}

#[test]
fn non_ask_outcomes_pass_through_without_ledger_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));
    let cfg = config(&ledger, Duration::from_secs(1));

    // An allowed command executes immediately; a denied one is denied — neither
    // should touch the approval ledger.
    let allowed = guard()
        .run_until_approved(&bash("ls -la"), &NoopSandbox, &cfg)
        .expect("no sandbox error");
    assert!(matches!(allowed, RuntimeOutcome::Executed { .. }));

    let denied = guard()
        .run_until_approved(&bash("rm -rf /"), &NoopSandbox, &cfg)
        .expect("no sandbox error");
    assert!(matches!(denied, RuntimeOutcome::Denied { .. }));

    assert!(ledger.list_pending().expect("list").is_empty());
}

/// An expiry is a claim about a bound. The ledger has to carry the bound, or
/// nobody holding the ledger can tell a correct expiry from a premature one.
///
/// Before this, the deadline lived only as a process-local `Instant` in the
/// waiting loop: not serialisable, not comparable across processes, and never
/// written down. A reader saw that a request expired between two timestamps
/// and could not check whether the configured timeout was 150ms or 30 minutes.
#[test]
fn expired_request_records_the_deadline_that_expired_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));
    let timeout = Duration::from_millis(150);

    let outcome = guard()
        .run_until_approved(
            &bash("git push origin main"),
            &NoopSandbox,
            &config(&ledger, timeout),
        )
        .expect("no sandbox error");

    let request_id = match outcome {
        RuntimeOutcome::Denied { request_id, .. } => request_id,
        other => panic!("expected Denied, got {other:?}"),
    };

    let record = ledger.get(&request_id).expect("get").expect("present");
    assert_eq!(record.status, ApprovalStatus::Expired);

    let expires_at = record
        .expires_at
        .expect("an expired request must record the deadline it passed");

    // The bound is derivable from the record alone.
    let bound_ms = (expires_at - record.created_at).num_milliseconds();
    assert_eq!(
        bound_ms,
        timeout.as_millis() as i64,
        "recorded deadline must equal created_at plus the configured timeout"
    );

    // And the terminal decision is justified by it, checkable without config.
    let decided_at = record.decided_at.expect("expired record is decided");
    assert!(
        decided_at >= expires_at,
        "expiry claimed at {decided_at} but the recorded deadline was {expires_at}"
    );
}

/// The reader's own configuration must not change what the ledger says
/// happened. Two runs under different timeouts each carry their own bound, and
/// a checker that reads only the record reaches the same verdict for both.
#[test]
fn expiry_verdict_does_not_depend_on_the_readers_timeout() {
    fn expiry_is_justified(record: &agent_guard_sdk::ApprovalRecord) -> bool {
        match (record.expires_at, record.decided_at) {
            (Some(expires_at), Some(decided_at)) => decided_at >= expires_at,
            // No recorded bound means the claim is unverifiable, not fine.
            _ => false,
        }
    }

    for timeout in [Duration::from_millis(120), Duration::from_millis(400)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));

        let outcome = guard()
            .run_until_approved(
                &bash("git push origin main"),
                &NoopSandbox,
                &config(&ledger, timeout),
            )
            .expect("no sandbox error");

        let request_id = match outcome {
            RuntimeOutcome::Denied { request_id, .. } => request_id,
            other => panic!("expected Denied, got {other:?}"),
        };

        let record = ledger.get(&request_id).expect("get").expect("present");
        assert!(
            expiry_is_justified(&record),
            "expiry under timeout {timeout:?} was not checkable from the ledger"
        );
    }
}
