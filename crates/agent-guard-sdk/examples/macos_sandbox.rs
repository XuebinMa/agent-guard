use agent_guard_sdk::{Guard, GuardInput, Tool, Sandbox};
#[cfg(feature = "macos-sandbox")]
use agent_guard_sdk::SeatbeltSandbox;

fn main() {
    #[cfg(not(feature = "macos-sandbox"))]
    {
        println!("This example requires the 'macos-sandbox' feature.");
        println!("Run with: cargo run --example macos_sandbox --features macos-sandbox");
        return;
    }

    #[cfg(feature = "macos-sandbox")]
    {
        println!("=== agent-guard macOS Seatbelt Sandbox Demo ===\n");

        let guard = Guard::from_yaml(r#"
version: 1
default_mode: read_only
tools:
  bash:
    allow: ["*"]
"#).unwrap();

        let sandbox = SeatbeltSandbox;
        if !sandbox.is_available() {
            println!("macOS Seatbelt sandbox (sandbox-exec) is not available on this system.");
            return;
        }

        // 1. Try a read (should be allowed by policy and sandbox)
        println!("[TEST 1] Read /etc/hosts (Policy: ReadOnly, Sandbox: ReadOnly)");
        let input = GuardInput::new(Tool::Bash, r#"{"command":"cat /etc/hosts | head -n 5"}"#);
        match guard.execute(&input, &sandbox) {
            Ok(outcome) => println!("Outcome: {:?}\n", outcome),
            Err(e) => println!("Error: {:?}\n", e),
        }

        // 2. Try a write (should be allowed by policy but BLOCKED by sandbox)
        println!("[TEST 2] Write to /tmp/test_sandbox.txt (Policy: ReadOnly, Sandbox: Blocked)");
        let input = GuardInput::new(Tool::Bash, r#"{"command":"echo 'hello' > /tmp/test_sandbox.txt"}"#);
        match guard.execute(&input, &sandbox) {
            Ok(outcome) => {
                println!("Outcome: {:?}", outcome);
                // Note: sandbox-exec returns exit code 1 or similar for permission denied
            },
            Err(e) => println!("Error: {:?}", e),
        }
        println!();

        // 3. Try a write with WorkspaceWrite (should be allowed by both if in workspace)
        println!("[TEST 3] Write to workspace (Policy: WorkspaceWrite, Sandbox: Allowed)");
        let guard_write = Guard::from_yaml(r#"
version: 1
default_mode: workspace_write
"#).unwrap();
        
        // Ensure the working directory is set to current workspace
        let mut ctx = agent_guard_sdk::Context::default();
        ctx.working_directory = Some(std::env::current_dir().unwrap());
        
        let input = GuardInput::new(Tool::Bash, r#"{"command":"echo 'sandbox ok' > target/sandbox_test.txt"}"#)
            .with_context(ctx);
        
        match guard_write.execute(&input, &sandbox) {
            Ok(outcome) => println!("Outcome: {:?}\n", outcome),
            Err(e) => println!("Error: {:?}\n", e),
        }
    }
}
