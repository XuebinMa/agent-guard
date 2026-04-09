use agent_guard_core::{Context, Tool};
use agent_guard_sdk::{get_metrics, prometheus_client, Guard};
use prometheus_client::encoding::text::encode;

/// A simple example showing how to access and encode agent-guard metrics.
/// In a real application, you would serve this output over an HTTP /metrics endpoint.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize the Guard with a basic policy
    let yaml = r#"
version: 1
default_mode: read_only
"#;
    let guard = Guard::from_yaml(yaml)?;

    // 2. Perform some tool calls to generate metrics
    println!("Generating sample metrics...");
    let context = Context {
        agent_id: Some("example-agent".to_string()),
        session_id: Some("session-123".to_string()),
        actor: Some("user-456".to_string()),
        trust_level: agent_guard_core::TrustLevel::Trusted,
        working_directory: None,
    };

    // An allowed call
    guard.check_tool(Tool::Bash, r#"{"command":"ls"}"#, context.clone());

    // An allowed call (different tool name for demonstration)
    guard.check_tool(Tool::ReadFile, r#"{"path":"README.md"}"#, context.clone());

    // 3. Access the global registry and encode as Prometheus text format
    let metrics = get_metrics();
    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry)?;

    println!("\n--- Prometheus Metrics Output ---");
    println!("{}", buffer);
    println!("---------------------------------");

    Ok(())
}
