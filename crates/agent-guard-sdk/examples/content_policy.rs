//! Content-layer policy example — secret/PII enforcement on outbound content.
//!
//! The content layer is opt-in and off by default. Build it with the
//! `content` feature:
//!
//!   cargo run -p agent-guard-sdk --example content_policy --features content
//!
//! It demonstrates the three content modes:
//!   - `block` — deny the call when sensitive content is detected (decision path)
//!   - `mask`  — execute a redacted copy ([REDACTED:<label>]) (execution path)
//!   - `warn`  — execute as-is but emit a ContentFinding audit record
//!
//! Detection happens on the `WriteFile` content field and the `HttpRequest`
//! body field. Findings only ever expose the *kind* of data (e.g. "AWS Access
//! Key"), never the raw matched substring.

use agent_guard_sandbox::NoopSandbox;
use agent_guard_sdk::{
    guard::ExecuteOutcome, Context, Guard, GuardDecision, GuardInput, Tool, TrustLevel,
};

const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn main() {
    println!("=== agent-guard content-layer policy ===\n");

    block_mode_denies_secret();
    mask_mode_redacts_on_execution();
    warn_mode_allows_and_audits();

    println!("\nDone.");
}

/// `block` mode: a secret in an outbound HTTP body is denied at decision time.
fn block_mode_denies_secret() {
    let policy = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
    content:
      mode: block
      detect: [secrets, pii]
"#;
    let guard = Guard::from_yaml(policy).expect("policy parse failed");

    let payload =
        format!(r#"{{"url":"https://example.test","method":"POST","body":"api_key={AWS_KEY}"}}"#);
    let decision = guard.check_tool(Tool::HttpRequest, &payload, Context::default());

    println!("[block] POST with a secret in the body");
    match decision {
        GuardDecision::Deny { reason } => {
            println!("        -> DENY: {}", reason.message());
        }
        other => println!("        -> unexpected: {other}"),
    }
}

/// `mask` mode: a secret written to a file is replaced with a placeholder
/// before the write actually happens.
fn mask_mode_redacts_on_execution() {
    let dir = std::env::temp_dir().join("agent-guard-content-example");
    let _ = std::fs::create_dir_all(&dir);
    let target = dir.join("masked.txt");

    let policy = format!(
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
      detect: [secrets]
"#,
        dir.display()
    );
    let guard = Guard::from_yaml(&policy).expect("policy parse failed");

    let input = GuardInput {
        tool: Tool::WriteFile,
        payload: format!(
            r#"{{"path":"{}","content":"deploy key: {AWS_KEY}"}}"#,
            target.display()
        ),
        context: Context {
            trust_level: TrustLevel::Trusted,
            working_directory: Some(dir.clone()),
            ..Default::default()
        },
    };

    println!("\n[mask]  write_file containing a secret");
    match guard.execute(&input, &NoopSandbox) {
        Ok(ExecuteOutcome::Executed { .. }) => match std::fs::read_to_string(&target) {
            Ok(contents) => println!("        -> file on disk: {contents:?}"),
            Err(e) => println!("        -> could not read file: {e}"),
        },
        Ok(other) => println!("        -> not executed: {other:?}"),
        Err(e) => println!("        -> execution error: {e}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `warn` mode: the call executes unchanged, but a ContentFinding audit record
/// is emitted (visible via SIEM/audit sinks; not shown inline here).
fn warn_mode_allows_and_audits() {
    let policy = r#"
version: 1
default_mode: full_access
tools:
  http_request:
    mode: full_access
    content:
      mode: warn
      detect: [secrets]
"#;
    let guard = Guard::from_yaml(policy).expect("policy parse failed");

    let payload =
        format!(r#"{{"url":"https://example.test","method":"POST","body":"token={AWS_KEY}"}}"#);
    let decision = guard.check_tool(Tool::HttpRequest, &payload, Context::default());

    println!("\n[warn]  POST with a secret in the body");
    println!(
        "        -> decision: {decision} (a ContentFinding audit record is emitted on execute)"
    );
}
