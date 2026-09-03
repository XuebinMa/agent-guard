//! A host-reported outcome is a claim, and until now it arrived with nothing
//! to check it against.
//!
//! `RuntimeOutcome::Handoff` hands the action to the host, which runs it
//! outside the Guard and reports back an exit code. The record says where the
//! claim came from — `ExecutionReported`, `sandbox_type: "host-handoff"` —
//! which identifies its provenance. It carried no material another evaluator
//! could use to re-check it, so a reader had to take the host's word and
//! could not even tell whether anyone had vouched for it.
//!
//! What an attestation can and cannot do is worth stating plainly. It binds a
//! named host key to an exact claim, so the claim cannot be forged by a third
//! party or edited in the ledger without detection. It does not make the exit
//! code true: the execution happened outside the boundary, and no signature
//! inside the boundary can reach it. The point is that a reader can tell
//! which of the two situations they are in.

use agent_guard_sandbox::NoopSandbox;
use agent_guard_sdk::{
    parse_hex_signing_key, Context, Guard, GuardInput, HandoffResult, HostAttestation,
    RuntimeOutcome, Tool, TrustLevel,
};
use serde_json::Value;

const HOST_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn policy(audit_path: &std::path::Path) -> String {
    format!(
        r#"
version: 1
default_mode: workspace_write
tools:
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

fn read_input() -> GuardInput {
    GuardInput {
        tool: Tool::ReadFile,
        payload: r#"{"path":"/workspace/README.md"}"#.to_string(),
        context: Context {
            trust_level: TrustLevel::Trusted,
            working_directory: Some(std::path::PathBuf::from("/workspace")),
            ..Default::default()
        },
    }
}

fn records(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("read audit file")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Run one handoff and return the `execution_reported` record it produced.
fn reported_record(build_result: impl Fn(&str) -> HandoffResult) -> (tempfile::TempDir, Value) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let guard = Guard::from_yaml(&policy(&audit_path)).expect("guard init");

    let request_id = match guard.run(&read_input(), &NoopSandbox).expect("runtime run") {
        RuntimeOutcome::Handoff { request_id, .. } => request_id,
        other => panic!("expected Handoff, got {other:?}"),
    };

    guard.report_handoff_result(&request_id, build_result(&request_id));
    drop(guard);

    let record = records(&audit_path)
        .into_iter()
        .find(|r| r.get("type").and_then(Value::as_str) == Some("execution_reported"))
        .expect("the handoff must be audited");
    (dir, record)
}

/// Without an attestation the record must say so, rather than looking like
/// anything the Guard witnessed.
#[test]
fn bare_handoff_outcome_carries_no_revalidation_material() {
    let (_dir, record) = reported_record(|_| HandoffResult {
        exit_code: 0,
        duration_ms: 42,
        stderr: None,
        attestation: None,
    });

    assert_eq!(record["sandbox_type"].as_str(), Some("host-handoff"));
    assert!(
        record.get("host_attestation").is_none(),
        "an unattested outcome must not appear to carry one: {record}"
    );
}

/// With an attestation the record carries it, and it verifies against the
/// host's public key.
#[test]
fn attested_handoff_outcome_verifies_against_the_host_key() {
    let key = parse_hex_signing_key(HOST_KEY_HEX).expect("host key");
    let verifying_key = key.verifying_key();

    let (_dir, record) = reported_record(|request_id| HandoffResult {
        exit_code: 0,
        duration_ms: 42,
        stderr: None,
        attestation: Some(HostAttestation::create(&key, "host-a", request_id, 0, 42)),
    });

    let attestation: HostAttestation =
        serde_json::from_value(record["host_attestation"].clone()).expect("attestation parses");

    assert_eq!(attestation.key_id, "host-a");
    assert!(
        attestation.verify(&verifying_key),
        "the recorded attestation must verify against the host key"
    );
    assert!(attestation.describes(
        record["request_id"].as_str().expect("request_id"),
        record["exit_code"].as_i64().expect("exit_code") as i32,
        record["duration_ms"].as_u64().expect("duration_ms"),
    ));
}

/// A host that signs one outcome and reports another is not attesting to what
/// it reported. The Guard can catch that without holding any key, and must
/// not record the mismatch as if it backed the claim.
#[test]
fn attestation_describing_a_different_outcome_is_refused() {
    let key = parse_hex_signing_key(HOST_KEY_HEX).expect("host key");

    let (_dir, record) = reported_record(|request_id| HandoffResult {
        exit_code: 1,
        duration_ms: 42,
        // Signed for a success; reported as a failure.
        attestation: Some(HostAttestation::create(&key, "host-a", request_id, 0, 42)),
        stderr: None,
    });

    assert_eq!(record["exit_code"].as_i64(), Some(1));
    assert!(
        record.get("host_attestation").is_none(),
        "an attestation for a different claim must not be attached: {record}"
    );
}

/// Editing the ledger after the fact breaks the signature. This is the whole
/// of what an attestation buys, and it is worth pinning.
#[test]
fn editing_an_attested_record_breaks_its_signature() {
    let key = parse_hex_signing_key(HOST_KEY_HEX).expect("host key");
    let verifying_key = key.verifying_key();

    let (_dir, mut record) = reported_record(|request_id| HandoffResult {
        exit_code: 0,
        duration_ms: 42,
        stderr: None,
        attestation: Some(HostAttestation::create(&key, "host-a", request_id, 0, 42)),
    });

    let attestation: HostAttestation =
        serde_json::from_value(record["host_attestation"].clone()).expect("attestation parses");
    assert!(attestation.verify(&verifying_key));

    // A tamperer flips the outcome in the ledger line.
    record["exit_code"] = Value::from(1);

    assert!(
        !attestation.describes(
            record["request_id"].as_str().expect("request_id"),
            record["exit_code"].as_i64().expect("exit_code") as i32,
            record["duration_ms"].as_u64().expect("duration_ms"),
        ),
        "the attestation must no longer describe the edited record"
    );
}
