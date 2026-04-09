fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    {
        use agent_guard_core::{Context, Tool, TrustLevel};
        use agent_guard_sandbox::SeatbeltSandbox;
        use agent_guard_sdk::{ExecuteOutcome, Guard};

        println!("🛡️ agent-guard Example: macOS Seatbelt Sandbox");
        println!("==============================================\n");

        // 1. Initialize Guard
        let yaml = r#"
version: 1
default_mode: workspace_write
"#;
        let guard = Guard::from_yaml(yaml)?;

        // 2. Setup Sandbox and Context
        let sandbox = SeatbeltSandbox;
        let temp_dir = std::env::temp_dir().join("agent_guard_macos_test");
        std::fs::create_dir_all(&temp_dir)?;

        let context = Context {
            agent_id: Some("macos-agent".to_string()),
            session_id: Some("session-123".to_string()),
            actor: Some("user-456".to_string()),
            trust_level: TrustLevel::Trusted,
            working_directory: Some(temp_dir.clone()),
        };

        // 3. Test Authorized Write (Inside Workspace)
        println!("👉 Action: Writing to workspace (Expected: SUCCESS)");
        let input_ok = agent_guard_sdk::GuardInput {
            tool: Tool::Bash,
            payload: format!(
                r#"{{"command":"echo 'hello' > {}/test.txt"}}"#,
                temp_dir.display()
            ),
            context: context.clone(),
        };

        let res_ok = guard.execute(&input_ok, &sandbox)?;
        if let ExecuteOutcome::Executed { output, .. } = res_ok {
            println!("✅ Status: EXECUTED (Exit Code: {})\n", output.exit_code);
        }

        // 4. Test Unauthorized Write (Outside Workspace)
        println!("👉 Action: Writing to /etc (Expected: BLOCKED by OS)");
        let input_fail = agent_guard_sdk::GuardInput {
            tool: Tool::Bash,
            payload: r#"{"command":"echo 'hack' > /etc/agent_guard_test.txt"}"#.to_string(),
            context,
        };

        let res_fail = guard.execute(&input_fail, &sandbox)?;
        if let ExecuteOutcome::Executed { output, .. } = res_fail {
            println!("🔒 Status: BLOCKED by OS (Exit Code: {})", output.exit_code);
            println!("📝 Stderr: {}\n", output.stderr.trim());
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(temp_dir);
        println!("==============================================");
    }

    #[cfg(not(all(target_os = "macos", feature = "macos-sandbox")))]
    {
        println!("This example is intended for macOS with the 'macos-sandbox' feature enabled.");
    }

    Ok(())
}
