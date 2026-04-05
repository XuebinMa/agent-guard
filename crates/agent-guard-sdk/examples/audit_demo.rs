//! Audit demo — shows the JSONL audit event format written to stdout.
//!
//! Run: cargo run -p agent-guard-sdk --example audit_demo

use agent_guard_sdk::{Context, Guard, Tool, TrustLevel};

const POLICY: &str = r#"
version: 1
default_mode: workspace_write
tools:
  bash:
    deny:
      - prefix: "rm -rf"
    ask:
      - prefix: "git push"
audit:
  enabled: true
  output: stdout
  include_payload_hash: true
"#;

fn main() {
    eprintln!("--- audit events will appear below as JSONL ---\n");

    let guard = Guard::from_yaml(POLICY).expect("policy parse failed");

    let inputs: &[(&str, TrustLevel)] = &[
        ("ls -la", TrustLevel::Trusted),
        ("rm -rf /tmp/cache", TrustLevel::Trusted),
        ("git push origin main", TrustLevel::Trusted),
    ];

    for (cmd, trust) in inputs {
        let ctx = Context {
            trust_level: trust.clone(),
            session_id: Some("session-audit-demo".to_string()),
            agent_id: Some("audit-demo-agent".to_string()),
            actor: Some("ci-bot".to_string()),
            ..Default::default()
        };
        guard.check_tool(Tool::Bash, *cmd, ctx);
    }

    eprintln!("\n--- done ---");
}
