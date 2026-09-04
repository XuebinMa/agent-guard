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
      - regex: "^git\\s+push\\s+--force(?:\\s|$)"
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
fn destructive_validator_warning_remains_ask_without_a_stronger_policy_decision() {
    // The bash validator runs before policy and classifies `rm -rf <path>`
    // as DESTRUCTIVE_COMMAND → AskUser. Validator warnings participate in the
    // final strongest-decision merge: they can strengthen an allow, while a
    // later policy deny still wins. This policy has no stronger matching rule,
    // so the final decision remains ask. Pin that behaviour.
    //
    // The event must carry `cwd` and the target must sit INSIDE that
    // workspace: `validate_paths` runs ahead of `check_destructive`
    // (`bash/mod.rs`), so an out-of-workspace — or unverifiable — target is
    // denied by the path gate and never reaches the destructive classifier.
    // Before sec26 this case reached `ask` only because a missing `cwd`
    // silently disabled that gate.
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let target = dir.path().join("foo");
    let stdin = serde_json::json!({
        "cwd": dir.path().to_string_lossy(),
        "tool_name": "Bash",
        "tool_input": { "command": format!("rm -rf {}", target.to_string_lossy()) },
    })
    .to_string();
    let (stdout, _stderr, code) = run_hook(&policy, &stdin);
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
fn send_pack_enters_outbound_approval_at_the_real_hook() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());

    let send_pack = r#"{"tool_name":"Bash","tool_input":{"command":"git send-pack origin main"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, send_pack);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\"") && stdout.contains("git send-pack"),
        "send-pack must enter exact outbound approval: {stdout}"
    );
}

#[test]
fn modeled_launcher_preserves_policy_and_safe_local_work_at_the_real_hook() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());

    let forced_push = r#"{"tool_name":"Bash","tool_input":{"command":"ionice -c3 git push --force origin main"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, forced_push);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "modeled launcher must preserve the inner force deny: {stdout}"
    );
    assert!(
        std::fs::read_to_string(&audit)
            .expect("read audit")
            .contains("\"detection_kind\":\"modeled_execution\""),
        "modeled execution provenance must be audited"
    );

    let benign = r#"{"tool_name":"Bash","tool_input":{"command":"ionice -c3 cargo build"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, benign);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "modeled benign launcher must stay frictionless: {stdout}"
    );
}

#[test]
fn embedded_argv_candidate_preserves_policy_strength_at_the_real_hook() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());

    let ordinary =
        r#"{"tool_name":"Bash","tool_input":{"command":"firejail git push origin main"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, ordinary);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\"")
            && stdout.contains("conservative argv candidate")
            && stdout.contains("embedded_argv"),
        "embedded ordinary push must ask with honest provenance: {stdout}"
    );

    let forced =
        r#"{"tool_name":"Bash","tool_input":{"command":"firejail git push --force origin main"}}"#;
    let (stdout, _stderr, code) = run_hook(&policy, forced);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "embedded destructive push must remain deny: {stdout}"
    );
    assert!(
        std::fs::read_to_string(&audit)
            .expect("read audit")
            .contains("\"detection_kind\":\"embedded_argv\""),
        "embedded argv provenance must be audited"
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
    // A broken pipe here is the behaviour under test, not a failure. The kill
    // switch answers before any I/O -- `main` checks the env var and returns
    // approve without ever reading stdin -- so on a machine where the child
    // exits first, this write has no reader. Unwrapping it made the test
    // assert the opposite of what the hook promises, and it failed in CI for
    // exactly that reason.
    let _ = child.stdin.as_mut().unwrap().write_all(stdin.as_bytes());
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

/// The hint has to reach the JSON the agent's host actually reads. A unit
/// test proves the sentence is right; only this proves it is attached.
#[test]
fn a_refused_push_tells_the_reader_about_the_broker() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;

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
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait guard-hook");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("agent-guard push --remote origin --branch main"),
        "a refusal must carry the way out, got: {stdout}"
    );
}

/// A denial that has nothing to do with pushing must not carry push advice.
#[test]
fn an_unrelated_denial_carries_no_broker_hint() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let policy = write_policy(&dir, audit.to_str().unwrap());
    let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"sudo whoami"}}"#;

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
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait guard-hook");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("agent-guard push"),
        "advice on an unrelated denial trains people to ignore advice: {stdout}"
    );
}
