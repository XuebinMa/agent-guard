//! An anomaly verdict is an authority claim, and a claim needs material
//! another evaluator can check it with.
//!
//! The rate limiter and the deny fuse decide against in-memory `Vec<Instant>`
//! histories that are destructively pruned to the current window. Every call
//! also lands in the durable audit stream with a `DateTime<Utc>`, so the
//! evidence is not missing — but the decision was never made over the
//! persisted set. Replaying the audit log could not reproduce it, and the
//! emitted `AgentLocked` record said only that a lock happened.
//!
//! These tests read the emitted record and recompute the verdict from it.

use agent_guard_sandbox::NoopSandbox;
use agent_guard_sdk::{Context, Guard, GuardInput, Tool, TrustLevel};
use serde_json::Value;

/// The denied prefix is deliberately inert. The test needs a call the policy
/// refuses, not a call that would do damage if the policy ever failed open.
const DENIED_COMMAND: &str = "forbidden-probe --always-denied";

fn policy(audit_path: &std::path::Path, threshold: usize) -> String {
    format!(
        r#"
version: 1
default_mode: workspace_write
tools:
  bash:
    mode: workspace_write
    deny:
      - prefix: "forbidden-probe"
audit:
  enabled: true
  output: file
  file_path: "{}"
anomaly:
  enabled: true
  rate_limit:
    max_calls: 1000
    window_seconds: 60
  deny_fuse:
    enabled: true
    threshold: {threshold}
    window_seconds: 60
"#,
        audit_path.display()
    )
}

fn denied_call() -> GuardInput {
    GuardInput {
        tool: Tool::Bash,
        payload: format!(r#"{{"command":"{DENIED_COMMAND}"}}"#),
        context: Context {
            agent_id: Some("agent-1".to_string()),
            actor: Some("actor-1".to_string()),
            trust_level: TrustLevel::Trusted,
            working_directory: Some(std::path::PathBuf::from("/workspace")),
            ..Default::default()
        },
    }
}

fn audit_records(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("read audit file")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Drive an actor into the deny fuse and return the emitted lock record.
fn lock_record(threshold: usize) -> (tempfile::TempDir, Value) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let guard = Guard::from_yaml(&policy(&audit_path, threshold)).expect("guard init");

    // One more call than the threshold: the denials arm the fuse, the last
    // call observes it armed and locks.
    for _ in 0..=threshold {
        let _ = guard.run(&denied_call(), &NoopSandbox);
    }
    drop(guard);

    let all = audit_records(&audit_path);
    let record = all
        .iter()
        .find(|r| r.get("type").and_then(Value::as_str) == Some("agent_locked"))
        .cloned()
        .unwrap_or_else(|| {
            let types: Vec<&str> = all
                .iter()
                .filter_map(|r| r.get("type").and_then(Value::as_str))
                .collect();
            panic!(
                "a lock must reach the audit sink, not only a SIEM webhook; \
                 the file received only {types:?}"
            )
        });
    (dir, record)
}

/// Given only the emitted record, an evaluator must be able to re-derive the
/// verdict: the witnesses fall inside the stated window and reach the stated
/// threshold.
#[test]
fn agent_lock_carries_the_evidence_that_justifies_it() {
    let (_dir, record) = lock_record(3);

    let evidence = record
        .get("evidence")
        .unwrap_or_else(|| panic!("lock record carries no evidence: {record}"));

    let threshold = evidence["threshold"].as_u64().expect("threshold");
    let observed = evidence["observed"].as_u64().expect("observed");
    let window_seconds = evidence["window_seconds"].as_i64().expect("window_seconds");
    let witnesses = evidence["witnesses"].as_array().expect("witnesses");
    let truncated = evidence["truncated"].as_bool().expect("truncated");

    assert_eq!(evidence["rule"].as_str(), Some("deny_fuse"));
    assert!(
        observed >= threshold,
        "recorded observation {observed} does not reach the recorded threshold {threshold}"
    );
    assert!(!truncated, "this run cannot overflow the history cap");
    assert_eq!(
        witnesses.len() as u64,
        observed,
        "the recorded count must be backed by that many witnesses"
    );

    // Every witness lies inside the window the decision claims to have used.
    let decided_at = record["timestamp"]
        .as_str()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .expect("record timestamp");
    for witness in witnesses {
        let seen = witness
            .as_str()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .expect("witness timestamp");
        let age = (decided_at - seen).num_seconds();
        assert!(
            (0..=window_seconds).contains(&age),
            "witness {seen} is {age}s before the decision, outside the {window_seconds}s window"
        );
    }
}

/// The verdict must follow from the record rather than from whatever
/// configuration the reader happens to hold. Two runs under different
/// thresholds are each checked by one function that reads only the record.
#[test]
fn lock_verdict_does_not_depend_on_the_readers_threshold() {
    fn verdict_is_justified(record: &Value) -> bool {
        let Some(evidence) = record.get("evidence") else {
            return false;
        };
        match (
            evidence["observed"].as_u64(),
            evidence["threshold"].as_u64(),
            evidence["witnesses"].as_array(),
            evidence["truncated"].as_bool(),
        ) {
            (Some(observed), Some(threshold), Some(witnesses), Some(false)) => {
                observed >= threshold && witnesses.len() as u64 == observed
            }
            _ => false,
        }
    }

    for threshold in [2usize, 5] {
        let (_dir, record) = lock_record(threshold);
        assert!(
            verdict_is_justified(&record),
            "lock under threshold {threshold} was not checkable from its own record: {record}"
        );
    }
}
