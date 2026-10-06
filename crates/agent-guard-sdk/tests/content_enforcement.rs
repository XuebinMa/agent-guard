//! S6-4b integration: content-layer enforcement wired through `Guard::check`.
//!
//! These tests only compile with the `content` feature, since the enforcement
//! stage in `evaluate()` is gated behind it.
#![cfg(feature = "content")]

use agent_guard_sdk::{
    guard::ExecuteOutcome, AuditRecord, Context, DecisionCode, Guard, GuardDecision, GuardInput,
    Tool, TrustLevel,
};

/// Policy that allows http_request at the action layer but blocks outbound
/// content carrying secrets/PII.
const BLOCK_POLICY: &str = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
    content:
      mode: block
"#;

/// Same shape but Warn mode — content findings must not change the decision.
const WARN_POLICY: &str = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
    content:
      mode: warn
"#;

fn guard(yaml: &str) -> Guard {
    Guard::from_yaml(yaml).expect("policy parses")
}

// ── Input scanning (issue #99) ───────────────────────────────────────────────
//
// `Guard::check_content` scans host-supplied input text (e.g. a prompt before
// it reaches the LLM provider) against the top-level `input_content:` policy
// block. Unlike the outbound path, Mask hands the redacted text BACK to the
// host — the Guard never performs the LLM call itself.

const INPUT_BLOCK_POLICY: &str = r#"
version: 1
default_mode: workspace_write
input_content:
  mode: block
audit:
  enabled: false
anomaly:
  enabled: false
"#;

const INPUT_MASK_POLICY: &str = r#"
version: 1
default_mode: workspace_write
input_content:
  mode: mask
audit:
  enabled: false
anomaly:
  enabled: false
"#;

const INPUT_WARN_POLICY: &str = r#"
version: 1
default_mode: workspace_write
input_content:
  mode: warn
audit:
  enabled: false
anomaly:
  enabled: false
"#;

const SECRET_PROMPT: &str = "Summarize this config: aws_key=AKIAIOSFODNN7EXAMPLE region=us-east-1";

#[test]
fn input_block_flags_secret_in_prompt() {
    let g = guard(INPUT_BLOCK_POLICY);
    let outcome = g.check_content(SECRET_PROMPT, &Context::default());
    assert!(outcome.blocked, "block mode must flag the prompt");
    assert!(outcome.masked_text.is_none(), "block mode does not mask");
    assert!(
        outcome.labels.iter().any(|l| l == "AWS Access Key"),
        "labels identify the finding kind: {:?}",
        outcome.labels
    );
    // Labels only — the outcome must never echo the raw secret.
    assert!(!outcome.labels.iter().any(|l| l.contains("AKIA")));
}

#[test]
fn input_mask_returns_redacted_text_to_host() {
    let g = guard(INPUT_MASK_POLICY);
    let outcome = g.check_content(SECRET_PROMPT, &Context::default());
    assert!(!outcome.blocked, "mask mode does not block");
    let masked = outcome.masked_text.expect("mask returns redacted text");
    assert!(masked.contains("[REDACTED:AWS Access Key]"));
    assert!(!masked.contains("AKIAIOSFODNN7EXAMPLE"));
    // The rest of the prompt survives.
    assert!(masked.contains("Summarize this config"));
}

#[test]
fn input_warn_reports_labels_without_masking() {
    let g = guard(INPUT_WARN_POLICY);
    let outcome = g.check_content(SECRET_PROMPT, &Context::default());
    assert!(!outcome.blocked);
    assert!(outcome.masked_text.is_none(), "warn mode does not mask");
    assert!(
        !outcome.labels.is_empty(),
        "warn mode still reports findings"
    );
}

#[test]
fn input_clean_text_is_benign() {
    let g = guard(INPUT_BLOCK_POLICY);
    let outcome = g.check_content("What is the capital of France?", &Context::default());
    assert!(!outcome.blocked);
    assert!(outcome.masked_text.is_none());
    assert!(outcome.labels.is_empty());
}

#[test]
fn input_without_policy_is_benign() {
    // No `input_content:` block configured → no scanning, even with a secret.
    let g = guard(BLOCK_POLICY);
    let outcome = g.check_content(SECRET_PROMPT, &Context::default());
    assert!(!outcome.blocked);
    assert!(outcome.masked_text.is_none());
    assert!(outcome.labels.is_empty());
}

#[test]
fn block_mode_denies_http_body_with_secret() {
    let g = guard(BLOCK_POLICY);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"token=AKIAIOSFODNN7EXAMPLE"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    match decision {
        GuardDecision::Deny { reason } => {
            assert_eq!(reason.code(), DecisionCode::SensitiveContentBlocked);
            // The deny message must never echo the raw secret.
            assert!(!reason.message().contains("AKIAIOSFODNN7EXAMPLE"));
        }
        other => panic!("expected deny, got {other:?}"),
    }
}

#[test]
fn block_mode_allows_clean_http_body() {
    let g = guard(BLOCK_POLICY);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"hello world"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    assert_eq!(decision, GuardDecision::Allow);
}

#[test]
fn warn_mode_allows_even_with_secret() {
    let g = guard(WARN_POLICY);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"token=AKIAIOSFODNN7EXAMPLE"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    assert_eq!(decision, GuardDecision::Allow);
}

#[test]
fn no_content_policy_means_no_content_enforcement() {
    let yaml = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
"#;
    let g = guard(yaml);
    let payload = r#"{"url":"https://x.test","method":"POST","body":"token=AKIAIOSFODNN7EXAMPLE"}"#;

    let decision = g.check_tool(Tool::HttpRequest, payload, Context::default());

    assert_eq!(decision, GuardDecision::Allow);
}

/// End-to-end: Mask mode rewrites the executed WriteFile payload, so the file
/// on disk contains the redaction placeholder rather than the raw secret.
#[test]
fn mask_mode_writes_redacted_file_on_execution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let yaml = format!(
        r#"
version: 1
default_mode: workspace_write
tools:
  write_file:
    mode: workspace_write
    allow_paths:
      - "{}/**"
    content:
      mode: mask
audit:
  enabled: true
  output: file
  file_path: "{}"
"#,
        dir.path().display(),
        audit_path.display()
    );
    let g = Guard::from_yaml(&yaml).expect("policy parses");

    let target = dir.path().join("out.txt");
    let inp = GuardInput {
        tool: Tool::WriteFile,
        payload: format!(
            r#"{{"path":"{}","content":"token AKIAIOSFODNN7EXAMPLE end"}}"#,
            target.display()
        ),
        context: Context {
            trust_level: TrustLevel::Trusted,
            working_directory: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
    };

    let sandbox = agent_guard_sandbox::NoopSandbox;
    match g.execute(&inp, &sandbox).expect("no sandbox error") {
        ExecuteOutcome::Executed { .. } => {
            let contents = std::fs::read_to_string(&target).expect("read target");
            assert!(contents.contains("[REDACTED:AWS Access Key]"));
            assert!(!contents.contains("AKIAIOSFODNN7EXAMPLE"));
        }
        other => panic!("expected Executed, got {other:?}"),
    }
    drop(g);

    let records: Vec<AuditRecord> = std::fs::read_to_string(&audit_path)
        .expect("read audit file")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid audit record"))
        .collect();
    let request_ids: Vec<&str> = records
        .iter()
        .filter_map(|record| match record {
            AuditRecord::ToolCall(event) => Some(event.request_id.as_str()),
            AuditRecord::ExecutionStarted(event) | AuditRecord::ExecutionFinished(event) => {
                Some(event.request_id.as_str())
            }
            AuditRecord::ContentFinding(event) => Some(event.request_id.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        request_ids.len(),
        4,
        "unexpected audit records: {records:#?}"
    );
    assert!(
        request_ids
            .iter()
            .all(|request_id| *request_id == request_ids[0]),
        "content finding must share the execution request ID: {records:#?}"
    );
    assert!(
        records
            .iter()
            .any(|record| matches!(record, AuditRecord::ContentFinding(_))),
        "content finding must reach the configured local audit sink"
    );
}

/// A policy whose signature failed decides nothing. Every tool call is
/// denied; the input check used to be the one entry point that still asked
/// the unverified policy, so removing its `input_content` block let a prompt
/// carrying a secret through.
#[test]
fn input_check_fails_closed_under_a_policy_whose_signature_failed() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let signature = agent_guard_sdk::sign_policy(INPUT_BLOCK_POLICY, &key);

    let verified = Guard::from_signed_yaml(INPUT_BLOCK_POLICY, &public_key, &signature)
        .expect("verified guard");
    assert!(
        verified
            .check_content(SECRET_PROMPT, &Context::default())
            .blocked
    );
    assert!(
        !verified
            .check_content("What is the capital of France?", &Context::default())
            .blocked
    );

    for tampered in [
        // The block removed, and the block downgraded.
        "version: 1\ndefault_mode: workspace_write\n",
        INPUT_WARN_POLICY,
    ] {
        let guard = Guard::from_signed_yaml(tampered, &public_key, &signature)
            .expect("an unverified policy still constructs a Guard that denies");
        guard.set_audit_sink(Box::new(std::io::sink()));
        for text in [SECRET_PROMPT, "What is the capital of France?"] {
            let outcome = guard.check_content(text, &Context::default());
            assert!(
                outcome.blocked,
                "an unverified policy decided an input check: {outcome:?}"
            );
            assert!(outcome.masked_text.is_none());
        }
    }
}
