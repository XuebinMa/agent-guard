//! Windows Sandbox adopting the unified Sandbox trait.
//!
//! Run: cargo run -p agent-guard-sdk --example windows_sandbox --features windows-sandbox

use agent_guard_sdk::{Guard, GuardInput, Tool, Sandbox};

fn main() {
    println!("=== agent-guard Windows Sandbox adoption demo ===");

    let guard = Guard::from_yaml("version: 1\ndefault_mode: workspace_write")
        .expect("Failed to init guard");

    // Use default sandbox (will be JobObject on Windows, Noop on others)
    let sandbox = guard.default_sandbox();
    
    println!("Sandbox Name:     {}", sandbox.name());
    println!("Sandbox Type:     {}", sandbox.sandbox_type());
    
    let caps = sandbox.capabilities();
    println!("Capabilities:");
    println!("  - Syscall Filtering:   {}", caps.syscall_filtering);
    println!("  - Filesystem Isolation: {}", caps.filesystem_isolation);
    println!("  - Resource Limits:      {}", caps.resource_limits);
    println!("  - Process Tree Cleanup: {}", caps.process_tree_cleanup);

    if !sandbox.is_available() {
        println!("\n[INFO] JobObject sandbox not available on this platform.");
        println!("Falling back to Noop for demonstration purposes.");
    }

    let input = GuardInput::new(Tool::Bash, r#"{"command":"echo 'hello from sandbox'"}"#);
    
    println!("\nExecuting command...");
    match guard.execute(&input, sandbox.as_ref()) {
        Ok(outcome) => {
            println!("Result: {:?}", outcome);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
