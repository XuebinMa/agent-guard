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
