//! A public decision result must not mix fields from two policy snapshots.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use agent_guard_sdk::{
    AuditRecord, Guard, GuardDecision, GuardInput, PolicyVerificationStatus, RuntimeDecision, Tool,
};

const ALLOW_POLICY: &str = r#"
version: 1
default_mode: full_access
tools:
  bash:
    mode: full_access
audit:
  enabled: true
  output: stdout
anomaly:
  enabled: false
"#;

const REPLACEMENT_POLICY: &str = r#"
version: 1
default_mode: read_only
tools:
  bash:
    mode: read_only
audit:
  enabled: true
  output: stdout
anomaly:
  enabled: false
"#;

#[derive(Clone)]
struct BlockingSink {
    output: Arc<Mutex<Vec<u8>>>,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
    blocked_once: Arc<AtomicBool>,
}

impl std::io::Write for BlockingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.blocked_once.swap(true, Ordering::SeqCst) {
            self.entered.wait();
            self.release.wait();
        }
        self.output
            .lock()
            .map_err(|_| std::io::Error::other("snapshot test output poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn evaluation_metadata_and_audit_id_come_from_one_snapshot_during_reload() {
    let guard = Guard::from_yaml(ALLOW_POLICY).expect("guard init");
    let original_version = guard.policy_version();
    let replacement_version = Guard::from_yaml(REPLACEMENT_POLICY)
        .expect("replacement guard")
        .policy_version();
    let output = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    guard.set_audit_sink(Box::new(BlockingSink {
        output: output.clone(),
        entered: entered.clone(),
        release: release.clone(),
        blocked_once: Arc::new(AtomicBool::new(false)),
    }));
    let input = GuardInput::new(Tool::Bash, r#"{"command":"ls"}"#);

    let evaluation = std::thread::scope(|scope| {
        let evaluator = scope.spawn(|| guard.evaluate_decision(&input));
        entered.wait();
        let reloader =
            scope.spawn(|| guard.reload_from_signed_yaml(REPLACEMENT_POLICY, "00", "00"));

        let deadline = Instant::now() + Duration::from_secs(5);
        while guard.policy_version() != replacement_version {
            assert!(
                Instant::now() < deadline,
                "replacement snapshot was not installed"
            );
            std::thread::yield_now();
        }
        release.wait();
        reloader.join().expect("reload thread").expect("reload");
        evaluator.join().expect("evaluation thread")
    });

    assert_eq!(evaluation.policy_version, original_version);
    assert_eq!(
        evaluation.policy_verification.status,
        PolicyVerificationStatus::Unsigned
    );
    assert_eq!(evaluation.decision, GuardDecision::Allow);
    assert_eq!(evaluation.runtime_decision, RuntimeDecision::Execute);
    assert_eq!(
        guard.policy_verification().status,
        PolicyVerificationStatus::Invalid,
        "the test must actually replace the snapshot while evaluation is blocked"
    );

    let captured = output.lock().expect("output lock").clone();
    let records: Vec<AuditRecord> = String::from_utf8(captured)
        .expect("audit output is utf-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid audit record"))
        .collect();
    let tool_call = records
        .iter()
        .find_map(|record| match record {
            AuditRecord::ToolCall(event) => Some(event),
            _ => None,
        })
        .expect("tool-call audit record");
    assert_eq!(tool_call.request_id, evaluation.request_id);
    assert_eq!(tool_call.policy_version, original_version);
}
