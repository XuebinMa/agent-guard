fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        use agent_guard_core::{Context, Tool, TrustLevel};
        use agent_guard_sdk::{Guard, GuardInput};
        use agent_guard_sandbox::JobObjectSandbox;
        println!("🛡️ agent-guard Example: Windows Job Object Sandbox");
        println!("==============================================\n");

        // 1. Initialize Guard
        let yaml = r#"
version: 1
default_mode: workspace_write
"#;
        let guard = Guard::from_yaml(yaml)?;

        // 2. Setup Sandbox
        let sandbox = JobObjectSandbox;
        let caps = agent_guard_sdk::Sandbox::capabilities(&sandbox);

        println!("Sandbox Capabilities (UCM):");
        println!("  - FS Workspace Write: {}", caps.filesystem_write_workspace);
        println!("  - FS Global Write:    {}", caps.filesystem_write_global);
        println!("  - Network Any:        {}", caps.network_outbound_any);
        println!();

        // 3. Execution Example
        let temp_dir = std::env::temp_dir().join("agent_guard_windows_test");
        std::fs::create_dir_all(&temp_dir)?;

        let context = Context {
            agent_id: Some("windows-agent".to_string()),
            session_id: Some("session-123".to_string()),
            actor: Some("user-456".to_string()),
            trust_level: TrustLevel::Trusted,
            working_directory: Some(temp_dir.clone()),
        };

        println!("👉 Action: Agent calls 'echo hello'");
        let input = GuardInput {
            tool: Tool::Bash,
            payload: r#"{"command":"echo hello"}"#.to_string(),
            context,
        };

        let res = guard.execute(&input, &sandbox)?;
        if let agent_guard_sdk::ExecuteOutcome::Executed { output, .. } = res {
            println!("✅ Status: EXECUTED");
            println!("📝 Stdout: {}", output.stdout.trim());
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(temp_dir);
        println!("\n==============================================");
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        println!("This example is intended for Windows systems.");
    }

    Ok(())
}
