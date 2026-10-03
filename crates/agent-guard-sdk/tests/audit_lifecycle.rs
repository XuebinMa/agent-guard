//! One evaluated request must produce one correlated audit lifecycle.

use agent_guard_sandbox::{
    NoopSandbox, Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxResult,
};
use agent_guard_sdk::{
    AuditRecord, Context, DecisionCode, Guard, GuardDecision, GuardInput, HandoffReportError,
    HandoffResult, RuntimeOutcome, Tool, TrustLevel,
};
use std::sync::{Arc, Mutex};

fn policy(audit_path: &std::path::Path) -> String {
    format!(
        r#"
version: 1
default_mode: full_access
tools:
  bash:
    mode: full_access
  read_file: {{}}
audit:
  enabled: true
  output: file
  file_path: "{}"
anomaly:
  enabled: false
"#,
        audit_path.display()
    )
}

fn input(tool: Tool, payload: &str) -> GuardInput {
    GuardInput {
        tool,
        payload: payload.to_string(),
        context: Context {
            trust_level: TrustLevel::Trusted,
            agent_id: Some("audit-lifecycle-agent".to_string()),
            working_directory: Some(std::env::temp_dir()),
            ..Default::default()
        },
    }
}

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut output = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("shared audit buffer poisoned"))?;
        output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FailingSandbox;

impl Sandbox for FailingSandbox {
    fn name(&self) -> &'static str {
        "failing-test-sandbox"
    }

    fn sandbox_type(&self) -> &'static str {
        "failing-test"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            filesystem_read_workspace: false,
            filesystem_read_global: false,
            filesystem_write_workspace: false,
            filesystem_write_global: false,
            network_outbound_any: false,
            network_outbound_internet: false,
            network_outbound_local: false,
            child_process_spawn: false,
            registry_write: false,
        }
    }

    fn execute(&self, _command: &str, _context: &SandboxContext) -> SandboxResult {
        Err(SandboxError::ExecutionFailed(
            "injected sandbox failure".to_string(),
        ))
    }

    fn is_available(&self) -> bool {
        true
    }
}

fn records(path: &std::path::Path) -> Vec<AuditRecord> {
    std::fs::read_to_string(path)
        .expect("read audit file")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid audit record"))
        .collect()
}

fn request_id(record: &AuditRecord) -> Option<&str> {
    match record {
        AuditRecord::ToolCall(event) => Some(&event.request_id),
        AuditRecord::ExecutionStarted(event)
        | AuditRecord::ExecutionFinished(event)
        | AuditRecord::ExecutionReported(event) => Some(&event.request_id),
        AuditRecord::SandboxFailure(event) => Some(&event.request_id),
        AuditRecord::ContentFinding(event) => Some(&event.request_id),
        AuditRecord::AnomalyTriggered(event) | AuditRecord::AgentLocked(event) => {
            event.request_id.as_deref()
        }
        AuditRecord::PolicyReload(_) => None,
    }
}

#[test]
fn executed_run_emits_one_decision_and_one_correlated_terminal_pair() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let guard = Guard::from_yaml(&policy(&audit_path)).expect("guard init");

    let outcome = guard
        .run(
            &input(Tool::Bash, r#"{"command":"printf lifecycle"}"#),
            &NoopSandbox,
        )
        .expect("runtime run");
    let returned_id = match outcome {
        RuntimeOutcome::Executed { request_id, .. } => request_id,
        other => panic!("expected executed outcome, got {other:?}"),
    };
    drop(guard);

    let records = records(&audit_path);
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(record, AuditRecord::ToolCall(_)))
            .count(),
        1,
        "run must not evaluate/audit the tool twice: {records:#?}"
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(record, AuditRecord::ExecutionStarted(_)))
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(record, AuditRecord::ExecutionFinished(_)))
            .count(),
        1
    );
    assert_eq!(
        records.len(),
        3,
        "unexpected lifecycle records: {records:#?}"
    );
    assert!(
        records
            .iter()
            .all(|record| request_id(record) == Some(returned_id.as_str())),
        "every lifecycle record must use the returned request ID: {records:#?}"
    );
}

#[test]
fn handoff_run_and_report_share_one_decision_start_and_terminal_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let guard = Guard::from_yaml(&policy(&audit_path)).expect("guard init");

    let outcome = guard
        .run(
            &input(Tool::ReadFile, r#"{"path":"README.md"}"#),
            &NoopSandbox,
        )
        .expect("runtime run");
    let returned_id = match outcome {
        RuntimeOutcome::Handoff { request_id, .. } => request_id,
        other => panic!("expected handoff outcome, got {other:?}"),
    };
    guard
        .try_report_handoff_result(
            &returned_id,
            HandoffResult {
                exit_code: 0,
                duration_ms: 7,
                stderr: None,
                attestation: None,
            },
        )
        .expect("pending handoff report");
    drop(guard);

    let records = records(&audit_path);
    assert_eq!(records.len(), 3, "unexpected handoff records: {records:#?}");
    assert!(matches!(records[0], AuditRecord::ToolCall(_)));
    assert!(matches!(records[1], AuditRecord::ExecutionStarted(_)));
    assert!(matches!(records[2], AuditRecord::ExecutionReported(_)));
    match &records[2] {
        AuditRecord::ExecutionReported(event) => {
            assert_eq!(event.tool, "read_file");
            assert_eq!(event.agent_id.as_deref(), Some("audit-lifecycle-agent"));
        }
        _ => unreachable!(),
    }
    assert!(
        records
            .iter()
            .all(|record| request_id(record) == Some(returned_id.as_str())),
        "handoff lifecycle must remain correlated: {records:#?}"
    );
}

#[test]
fn non_file_sink_receives_the_complete_execution_lifecycle() {
    let guard = Guard::from_yaml(
        r#"
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
"#,
    )
    .expect("guard init");
    let buffer = Arc::new(Mutex::new(Vec::new()));
    guard.set_audit_sink(Box::new(SharedBuf(buffer.clone())));

    let outcome = guard
        .run(
            &input(Tool::Bash, r#"{"command":"printf lifecycle"}"#),
            &NoopSandbox,
        )
        .expect("runtime run");
    let returned_id = match outcome {
        RuntimeOutcome::Executed { request_id, .. } => request_id,
        other => panic!("expected executed outcome, got {other:?}"),
    };

    let captured = buffer.lock().expect("audit buffer lock").clone();
    let records: Vec<AuditRecord> = String::from_utf8(captured)
        .expect("audit output is utf-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid audit record"))
        .collect();
    assert_eq!(records.len(), 3, "unexpected records: {records:#?}");
    assert!(matches!(records[0], AuditRecord::ToolCall(_)));
    assert!(matches!(records[1], AuditRecord::ExecutionStarted(_)));
    assert!(matches!(records[2], AuditRecord::ExecutionFinished(_)));
    assert!(
        records
            .iter()
            .all(|record| request_id(record) == Some(returned_id.as_str())),
        "the non-file sink must preserve lifecycle correlation: {records:#?}"
    );
}

#[test]
fn non_file_sink_receives_the_complete_handoff_lifecycle() {
    let guard = Guard::from_yaml(
        r#"
version: 1
default_mode: full_access
tools:
  read_file: {}
audit:
  enabled: true
  output: stdout
anomaly:
  enabled: false
"#,
    )
    .expect("guard init");
    let buffer = Arc::new(Mutex::new(Vec::new()));
    guard.set_audit_sink(Box::new(SharedBuf(buffer.clone())));

    let outcome = guard
        .run(
            &input(Tool::ReadFile, r#"{"path":"README.md"}"#),
            &NoopSandbox,
        )
        .expect("runtime run");
    let returned_id = match outcome {
        RuntimeOutcome::Handoff { request_id, .. } => request_id,
        other => panic!("expected handoff outcome, got {other:?}"),
    };
    guard
        .try_report_handoff_result(
            &returned_id,
            HandoffResult {
                exit_code: 0,
                duration_ms: 11,
                stderr: None,
                attestation: None,
            },
        )
        .expect("pending handoff report");

    let captured = buffer.lock().expect("audit buffer lock").clone();
    let records: Vec<AuditRecord> = String::from_utf8(captured)
        .expect("audit output is utf-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid audit record"))
        .collect();
    assert_eq!(records.len(), 3, "unexpected records: {records:#?}");
    assert!(matches!(records[0], AuditRecord::ToolCall(_)));
    assert!(matches!(records[1], AuditRecord::ExecutionStarted(_)));
    assert!(matches!(records[2], AuditRecord::ExecutionReported(_)));
    assert!(
        records
            .iter()
            .all(|record| request_id(record) == Some(returned_id.as_str())),
        "the non-file sink must preserve handoff correlation: {records:#?}"
    );
}

#[test]
fn sandbox_error_is_the_correlated_terminal_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let guard = Guard::from_yaml(&policy(&audit_path)).expect("guard init");

    let error = guard
        .run(
            &input(Tool::Bash, r#"{"command":"printf never-runs"}"#),
            &FailingSandbox,
        )
        .expect_err("the injected sandbox failure must reach the caller");
    assert!(error.to_string().contains("injected sandbox failure"));
    drop(guard);

    let records = records(&audit_path);
    assert_eq!(records.len(), 3, "unexpected records: {records:#?}");
    assert!(matches!(records[0], AuditRecord::ToolCall(_)));
    assert!(matches!(records[1], AuditRecord::ExecutionStarted(_)));
    assert!(matches!(records[2], AuditRecord::SandboxFailure(_)));
    assert!(
        !records
            .iter()
            .any(|record| matches!(record, AuditRecord::ExecutionFinished(_))),
        "a failed sandbox execution must not be recorded as finished"
    );
    let evaluated_id = request_id(&records[0]).expect("tool call request ID");
    assert!(
        records
            .iter()
            .all(|record| request_id(record) == Some(evaluated_id)),
        "the sandbox failure must remain correlated: {records:#?}"
    );
}

#[test]
fn handoff_report_uses_the_original_snapshot_and_is_one_shot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original_audit = dir.path().join("original.jsonl");
    let replacement_audit = dir.path().join("replacement.jsonl");
    let guard = Guard::from_yaml(&policy(&original_audit)).expect("guard init");

    let outcome = guard
        .run(
            &input(Tool::ReadFile, r#"{"path":"README.md"}"#),
            &NoopSandbox,
        )
        .expect("runtime run");
    let returned_id = match outcome {
        RuntimeOutcome::Handoff { request_id, .. } => request_id,
        other => panic!("expected handoff outcome, got {other:?}"),
    };

    guard
        .reload_from_yaml(&policy(&replacement_audit))
        .expect("policy reload");
    let result = HandoffResult {
        exit_code: 0,
        duration_ms: 13,
        stderr: None,
        attestation: None,
    };
    guard
        .try_report_handoff_result(&returned_id, result.clone())
        .expect("the original pending handoff survives policy reload");
    assert!(matches!(
        guard.try_report_handoff_result(&returned_id, result.clone()),
        Err(HandoffReportError::UnknownRequest { .. })
    ));
    assert!(matches!(
        guard.try_report_handoff_result("invented-request", result),
        Err(HandoffReportError::UnknownRequest { .. })
    ));

    let _ = guard.check(&input(Tool::Bash, r#"{"command":"printf replacement"}"#));
    drop(guard);

    let original = records(&original_audit);
    assert_eq!(
        original.len(),
        4,
        "unexpected original records: {original:#?}"
    );
    assert!(matches!(original[0], AuditRecord::ToolCall(_)));
    assert!(matches!(original[1], AuditRecord::ExecutionStarted(_)));
    assert!(matches!(original[2], AuditRecord::PolicyReload(_)));
    assert!(matches!(original[3], AuditRecord::ExecutionReported(_)));
    for record in [&original[0], &original[1], &original[3]] {
        assert_eq!(request_id(record), Some(returned_id.as_str()));
    }

    let replacement = records(&replacement_audit);
    assert_eq!(
        replacement.len(),
        1,
        "the handoff terminal must not move to the replacement sink: {replacement:#?}"
    );
    assert!(matches!(replacement[0], AuditRecord::ToolCall(_)));
}

#[test]
fn anomaly_sideband_record_carries_the_decision_request_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let guard = Guard::from_yaml(&format!(
        r#"
version: 1
default_mode: workspace_write
tools:
  bash:
    mode: workspace_write
audit:
  enabled: true
  output: file
  file_path: "{}"
anomaly:
  enabled: true
  rate_limit:
    window_seconds: 60
    max_calls: 1
"#,
        audit_path.display()
    ))
    .expect("guard init");
    let probe = input(Tool::Bash, r#"{"command":"ls"}"#);

    assert_eq!(guard.check(&probe), GuardDecision::Allow);
    match guard.check(&probe) {
        GuardDecision::Deny { reason } => {
            assert_eq!(reason.code(), DecisionCode::AnomalyDetected)
        }
        other => panic!("expected anomaly denial, got {other:?}"),
    }
    drop(guard);

    let records = records(&audit_path);
    let anomaly_id = records
        .iter()
        .find_map(|record| match record {
            AuditRecord::AnomalyTriggered(event) => event.request_id.as_deref(),
            _ => None,
        })
        .expect("anomaly record has request ID");
    let matching_decision = records.iter().find_map(|record| match record {
        AuditRecord::ToolCall(event) if event.request_id == anomaly_id => Some(event),
        _ => None,
    });
    assert!(
        matching_decision.is_some_and(|event| event.code == Some(DecisionCode::AnomalyDetected)),
        "anomaly sideband and tool decision must correlate: {records:#?}"
    );
}

#[test]
fn disabled_audit_keeps_recent_handoffs_reportable_without_exhaustion() {
    let guard = Guard::from_yaml(
        r#"
version: 1
default_mode: workspace_write
tools:
  read_file: {}
audit:
  enabled: false
anomaly:
  enabled: false
"#,
    )
    .expect("guard init");
    let probe = input(Tool::ReadFile, r#"{"path":"README.md"}"#);

    let mut first_id = None;
    let mut latest_id = None;
    for index in 0..4_100 {
        let outcome = guard
            .run(&probe, &NoopSandbox)
            .unwrap_or_else(|error| panic!("disabled audit handoff {index} failed: {error}"));
        let RuntimeOutcome::Handoff { request_id, .. } = outcome else {
            panic!("expected handoff at call {index}, got {outcome:?}");
        };
        first_id.get_or_insert_with(|| request_id.clone());
        latest_id = Some(request_id);
    }

    let result = HandoffResult {
        exit_code: 0,
        duration_ms: 1,
        stderr: None,
        attestation: None,
    };
    guard
        .try_report_handoff_result(
            latest_id.as_deref().expect("latest handoff ID"),
            result.clone(),
        )
        .expect("a recent audit-disabled handoff remains reportable");
    assert!(matches!(
        guard.try_report_handoff_result(
            latest_id.as_deref().expect("latest handoff ID"),
            result.clone()
        ),
        Err(HandoffReportError::UnknownRequest { .. })
    ));
    assert!(matches!(
        guard.try_report_handoff_result(first_id.as_deref().expect("first handoff ID"), result),
        Err(HandoffReportError::UnknownRequest { .. })
    ));
}

#[test]
fn audit_disabled_overflow_never_evicts_an_audited_handoff() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let guard = Guard::from_yaml(&policy(&audit_path)).expect("guard init");
    let probe = input(Tool::ReadFile, r#"{"path":"README.md"}"#);

    let audited_id = match guard.run(&probe, &NoopSandbox).expect("audited handoff") {
        RuntimeOutcome::Handoff { request_id, .. } => request_id,
        other => panic!("expected audited handoff, got {other:?}"),
    };
    guard
        .reload_from_yaml(
            r#"
version: 1
default_mode: workspace_write
tools:
  read_file: {}
audit:
  enabled: false
anomaly:
  enabled: false
"#,
        )
        .expect("disable audit");

    for index in 0..4_100 {
        assert!(
            matches!(
                guard.run(&probe, &NoopSandbox),
                Ok(RuntimeOutcome::Handoff { .. })
            ),
            "audit-disabled overflow must preserve audited entries at call {index}"
        );
    }

    guard
        .try_report_handoff_result(
            &audited_id,
            HandoffResult {
                exit_code: 0,
                duration_ms: 1,
                stderr: None,
                attestation: None,
            },
        )
        .expect("the audited pending lifecycle must not be evicted");
    drop(guard);

    let records = records(&audit_path);
    assert!(records.iter().any(|record| {
        matches!(record, AuditRecord::ExecutionReported(event) if event.request_id == audited_id)
    }));
}
