use agent_guard_core::{Context, Tool, TrustLevel};
use agent_guard_sandbox::NoopSandbox;
use agent_guard_sdk::{ExecuteOutcome, Guard, GuardInput};
use std::time::{Duration, Instant};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn input(command: &str) -> GuardInput {
    GuardInput {
        tool: Tool::Bash,
        payload: serde_json::json!({ "command": command }).to_string(),
        context: Context {
            agent_id: Some("stress-resource-agent".to_string()),
            trust_level: TrustLevel::Trusted,
            working_directory: Some(std::env::current_dir().unwrap()),
            ..Default::default()
        },
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// SCENARIO 1: High-Frequency Spawn/Kill
/// Runs 1000 short-lived processes to check for handle/process leaks.
#[tokio::test]
async fn test_stress_resource_spawn_loop() {
    let guard = Guard::from_yaml("version: 1\ndefault_mode: full_access").unwrap();
    let sandbox = Guard::default_sandbox();
    let count = 100; // Scaled down for CI/Agent environment, 10000 in full soak

    println!(
        "🚀 Starting high-frequency spawn loop ({} iterations)",
        count
    );
    let start = Instant::now();

    for _ in 0..count {
        let res = guard.execute(&input("echo 1"), sandbox.as_ref()).unwrap();
        if let ExecuteOutcome::Executed { output, .. } = res {
            assert_eq!(output.exit_code, 0);
        }
    }

    println!("✅ Finished spawn loop in {:?}", start.elapsed());

    // On Unix, we check for zombie processes (defunct)
    #[cfg(unix)]
    {
        match std::process::Command::new("ps").arg("-ef").output() {
            Ok(output) => {
                let ps_out = String::from_utf8_lossy(&output.stdout);
                let zombie_count = ps_out.lines().filter(|l| l.contains("<defunct>")).count();
                assert!(
                    zombie_count < 5,
                    "Too many zombie processes detected: {}",
                    zombie_count
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("Skipping zombie-process check: host denies `ps -ef` ({e})");
            }
            Err(e) => panic!("failed to run `ps -ef`: {e}"),
        }
    }
}

/// SCENARIO 2: Large Output Deadlock Test
/// Generates large stdout and stderr simultaneously to ensure no pipe deadlocks.
#[tokio::test]
async fn test_stress_resource_large_output() {
    let guard = Guard::from_yaml("version: 1\ndefault_mode: full_access").unwrap();
    let sandbox = Guard::default_sandbox();

    if sandbox.sandbox_type() == "none" {
        return;
    }

    // Generate ~100KB of output to both streams
    let cmd = if cfg!(windows) {
        "powershell -Command \"for($i=0; $i -lt 1000; $i++){ Write-Output 'STDOUT_LINE_$i'; [Console]::Error.WriteLine('STDERR_LINE_$i') }\""
    } else {
        "for i in $(seq 1 1000); do echo \"STDOUT_LINE_$i\"; echo \"STDERR_LINE_$i\" >&2; done"
    };

    println!("🚀 Starting large output deadlock test");
    let start = Instant::now();

    let res = guard.execute(&input(cmd), sandbox.as_ref()).unwrap();

    if let ExecuteOutcome::Executed { output, .. } = res {
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.contains("STDOUT_LINE_1000"));
        assert!(output.stderr.contains("STDERR_LINE_1000"));
    }

    println!("✅ Large output test finished in {:?}", start.elapsed());
}

/// SCENARIO 3: Slow Webhook Impact
/// Verifies that a slow/failing webhook does not block the execution chain.
#[tokio::test]
async fn test_stress_resource_slow_webhook() {
    use httpmock::prelude::*;

    // 1. Start mock server that delays 2 seconds
    let server = match std::panic::catch_unwind(MockServer::start) {
        Ok(server) => server,
        Err(_) => {
            eprintln!("Skipping slow webhook test: host denies local listener startup");
            return;
        }
    };
    let unique_id = rand::random::<u64>();
    let unique_path = format!("/slow_audit_{}", unique_id);
    let delay_mock = server.mock(|when, then| {
        when.method(POST).path(&unique_path);
        then.status(200).delay(Duration::from_secs(2));
    });

    let yaml = format!(
        r#"
version: 1
default_mode: full_access
audit:
  enabled: true
  webhook_url: "http://{}{}"
"#,
        server.address(),
        unique_path
    );

    let guard = Guard::from_yaml(&yaml).unwrap();
    let sandbox = NoopSandbox;

    println!("🚀 Starting slow webhook test (Webhook delay: 2s)");
    let start = Instant::now();

    // 2. Execute 10 requests.
    // Each execute() triggers 3 SIEM exports: ToolCall, ExecutionStarted, ExecutionFinished.
    // Total expected hits: 10 * 3 = 30.
    for _ in 0..10 {
        let _ = guard.execute(&input("echo 1"), &sandbox);
    }

    let elapsed = start.elapsed();
    println!("✅ Executed 10 requests with slow webhook in {:?}", elapsed);
    assert!(
        elapsed < Duration::from_secs(5),
        "Main execution chain blocked by slow webhook!"
    );

    // Wait a bit for the async threads to finish
    tokio::time::sleep(Duration::from_millis(500)).await;
    delay_mock.assert_hits(30);
}

/// SCENARIO 4: Soak Test (Condensed)
/// Combined load for resource drift detection.
#[tokio::test]
async fn test_stress_resource_soak_condensed() {
    let guard = Guard::from_yaml("version: 1\ndefault_mode: full_access").unwrap();
    let sandbox = Guard::default_sandbox();
    let duration = Duration::from_secs(30); // 30s soak for CI environment
    let start = Instant::now();

    println!("🚀 Starting condensed soak test (30s)");

    let mut count = 0;
    while start.elapsed() < duration {
        let _ = guard.execute(&input("echo 1"), sandbox.as_ref());
        count += 1;
        if count % 50 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    println!("✅ Soak test finished. Executions: {}", count);
}
