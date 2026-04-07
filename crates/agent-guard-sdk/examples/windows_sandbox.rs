//! Windows Job Object Sandbox Example
//!
//! Demonstrates the experimental Windows sandbox implementation focusing on
//! process tree management and resource restrictions.
//!
//! Run: cargo run -p agent-guard-sdk --example windows_sandbox --features windows-sandbox

use agent_guard_sdk::{Guard, GuardInput, Tool, Sandbox};

fn main() {
    println!("=== agent-guard Windows Sandbox Example ===");

    // 1. Initialize Guard with a simple policy
    let yaml = r#"
version: 1
default_mode: workspace_write
"#;
    let guard = Guard::from_yaml(yaml).expect("Failed to create guard");

    // 2. Identify and describe the sandbox
    let sandbox = guard.default_sandbox();
    println!("Active Sandbox: {}", sandbox.name());
    println!("Type:           {}", sandbox.sandbox_type());
    
    let caps = sandbox.capabilities();
    println!("Capabilities:");
    println!("  - Syscall Filtering:   {}", caps.syscall_filtering);
    println!("  - Filesystem Isolation: {}", caps.filesystem_isolation);
    println!("  - Resource Limits:      {}", caps.resource_limits);
    println!("  - Process Tree Cleanup: {}", caps.process_tree_cleanup);

    if !sandbox.is_available() {
        println!("\n[SKIP] This example requires Windows to demonstrate Job Object behavior.");
        return;
    }

    // 3. Execute a command within the sandbox
    println!("\nExecuting 'dir' in a restricted Job Object...");
    let input = GuardInput::new(Tool::Bash, r#"{"command":"dir"}"#);
    
    // Use execute() which leverages the default sandbox
    match guard.execute(&input) {
        Ok(outcome) => {
            println!("Outcome: {}", outcome.outcome);
            println!("Exit Code: {}", outcome.output.exit_code);
            println!("STDOUT (first 100 chars):\n{}", &outcome.output.stdout.chars().take(100).collect::<String>());
        }
        Err(e) => {
            eprintln!("Execution Failed: {}", e);
        }
    }

    println!("\n[INFO] When this process exits, the Job Object handle will be closed,");
    println!("automatically terminating any orphaned child processes spawned by the command.");
    println!("Done.");
}
