//! End-to-end tests for the guard-hook binary.
//!
//! Spawns the compiled binary with stdin JSON and asserts:
//! - stdout carries the correct permissionDecision for allow/deny/ask paths
//! - audit JSONL records appear in the configured file when audit.output=file

use std::io::Write;
use std::process::{Command, Stdio};

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_guard-hook");

fn write_policy(dir: &TempDir, audit_path: &str) -> std::path::PathBuf {
    let policy = format!(
        r#"
version: 1
default_mode: workspace_write

tools:
  bash:
    mode: workspace_write
    deny:
      - prefix: "sudo"
    ask:
      - prefix: "git push"
    allow:
      - prefix: "ls"

trust:
  untrusted:
    override_mode: workspace_write

audit:
  enabled: true
  output: file
  file_path: "{audit_path}"
  include_payload_hash: true
"#,
        audit_path = audit_path
    );
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, policy).expect("write policy");
    path
}

fn run_hook(policy: &std::path::Path, stdin_json: &str) -> (String, String, i32) {
    let mut child = Command::new(BIN)
        .args([
            "check",
            "--policy",
            policy.to_str().unwrap(),
            "--agent-id",
            "e2e-test",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn guard-hook");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_json.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait guard-hook");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

#[test]
fn allows_safe_bash_command() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, stdin);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "expected allow, got: {stdout}"
    );
}

#[test]
fn denies_sudo_command() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"sudo apt-get install foo"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, stdin);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "expected deny, got: {stdout}"
    );
}

#[test]
fn destructive_validator_short_circuits_to_ask() {
    // The bash validator runs before policy and classifies `rm -rf <path>`
    // as DESTRUCTIVE_COMMAND → AskUser. This is by design: validator
    // detections take precedence over policy rules so users can't
    // accidentally allow inherently destructive commands. Pin the behaviour.
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/foo"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, stdin);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "validator should ask on rm -rf, got: {stdout}"
    );
    assert!(
        stdout.contains("DESTRUCTIVE_COMMAND"),
        "reason should carry DESTRUCTIVE_COMMAND code: {stdout}"
    );
}

#[test]
fn asks_on_git_push() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, stdin);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "expected ask, got: {stdout}"
    );
}

#[test]
fn kill_switch_short_circuits_to_allow() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/foo"}}"#;
    let mut child = Command::new(BIN)
        .env("AGENT_GUARD_HOOK", "off")
        .args([
            "check",
            "--policy",
            policy.to_str().unwrap(),
            "--agent-id",
            "e2e-test",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn guard-hook");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait guard-hook");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "kill switch should allow even rm -rf, got: {stdout}"
    );
}

#[test]
fn audit_jsonl_receives_decision_record() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"sudo apt-get install foo"}}"#;
    let (_stdout, _stderr, _code) = run_hook(&policy, stdin);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if let Ok(meta) = std::fs::metadata(&audit) {
            if meta.len() > 0 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let body = std::fs::read_to_string(&audit).expect("audit file should exist");
    assert!(!body.is_empty(), "audit log should not be empty");
    assert!(
        body.contains("DENIED_BY_RULE"),
        "audit log should record DENIED_BY_RULE for sudo deny, got: {body}"
    );
    assert!(
        body.contains("\"tool\":\"bash\""),
        "audit log should include tool=bash, got: {body}"
    );
    assert!(
        body.contains("\"agent_id\":\"e2e-test\""),
        "audit log should include the configured agent_id, got: {body}"
    );
}

#[test]
fn unmappable_tool_silently_approves() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, stdin);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "Read is out-of-wedge, must allow: {stdout}"
    );
}
