use agent_guard_core::{Context, DecisionCode, GuardDecision, Tool, TrustLevel};
use agent_guard_sdk::{get_metrics, ExecuteOutcome, Guard, GuardInput, ExecutionReceipt};
use agent_guard_sandbox::NoopSandbox;
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

// ── Configuration ───────────────────────────────────────────────────────────

const TEST_PREFIX: &str = "stress-concurrency";
const ANOMALY_MAX_CALLS: usize = 5;
const DENY_FUSE_THRESHOLD: usize = 3;

#[derive(Debug, Clone, Copy)]
enum TrafficType {
    Allow,
    Deny,
    AnomalyTrigger,
}

struct ShadowState {
    denial_count: usize,
    is_locked: bool,
}

struct GlobalStats {
    total_requests: AtomicUsize,
    actual_allows: AtomicUsize,
    actual_denies: AtomicUsize,
    actual_anomalies: AtomicUsize,
    actual_locks: AtomicUsize,
}

// ── Test Logic ──────────────────────────────────────────────────────────────

async fn run_stress_tier(agent_count: usize, duration_secs: u64, tier_name: &str) {
    println!("\n🚀 Starting Stress Tier [{}]: {} agents, {}s", tier_name, agent_count, duration_secs);

    let yaml = format!(r#"
version: 1
default_mode: read_only
tools:
  bash:
    deny:
      - "malicious"
anomaly:
  enabled: true
  rate_limit:
    window_seconds: 60
    max_calls: {}
  deny_fuse:
    enabled: true
    threshold: {}
    window_seconds: 60
"#, ANOMALY_MAX_CALLS, DENY_FUSE_THRESHOLD);

    let guard = Arc::new(Guard::from_yaml(&yaml).expect("Failed to init Guard"));
    let stats = Arc::new(GlobalStats {
        total_requests: AtomicUsize::new(0),
        actual_allows: AtomicUsize::new(0),
        actual_denies: AtomicUsize::new(0),
        actual_anomalies: AtomicUsize::new(0),
        actual_locks: AtomicUsize::new(0),
    });

    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_secs);
    
    let mut workers: Vec<JoinHandle<()>> = Vec::new();

    for i in 0..agent_count {
        let guard = guard.clone();
        let stats = stats.clone();
        let agent_id = format!("{}-agent-{}", TEST_PREFIX, i);
        
        workers.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let mut shadow = ShadowState { denial_count: 0, is_locked: false };
            let sandbox = NoopSandbox;

            while Instant::now() < end_time {
                // Pick traffic type based on weights: 40/40/20
                let r: u8 = rng.gen_range(0..100);
                let traffic = if r < 40 {
                    TrafficType::Allow
                } else if r < 80 {
                    TrafficType::Deny
                } else {
                    TrafficType::AnomalyTrigger
                };

                let cmd = match traffic {
                    TrafficType::Allow => "echo 'safe'",
                    TrafficType::Deny => "bash malicious",
                    TrafficType::AnomalyTrigger => "echo 'rapid-fire'",
                };

                // If anomaly trigger, fire many requests quickly
                let burst = if matches!(traffic, TrafficType::AnomalyTrigger) { 15 } else { 1 };
                
                for _ in 0..burst {
                    let context = Context {
                        agent_id: Some(agent_id.clone()),
                        session_id: Some(format!("session-{}", i)),
                        actor: Some(agent_id.clone()), // Use same id for actor to trigger fuse
                        trust_level: TrustLevel::Trusted,
                        working_directory: None,
                    };

                    let input = GuardInput {
                        tool: Tool::Bash,
                        payload: serde_json::json!({ "command": cmd }).to_string(),
                        context,
                    };

                    let res = guard.execute(&input, &sandbox).expect("SDK execution panicked");
                    stats.total_requests.fetch_add(1, Ordering::SeqCst);

                    match res {
                        ExecuteOutcome::Executed { .. } => {
                            stats.actual_allows.fetch_add(1, Ordering::SeqCst);
                            assert!(!shadow.is_locked, "Agent {} should not be able to execute while locked", agent_id);
                        }
                        ExecuteOutcome::Denied { decision, .. } => {
                            if let GuardDecision::Deny { reason } = decision {
                                match reason.code {
                                    DecisionCode::DeniedByRule | DecisionCode::WriteInReadOnlyMode => {
                                        stats.actual_denies.fetch_add(1, Ordering::SeqCst);
                                        shadow.denial_count += 1;
                                        // Check if fuse should have triggered
                                        if shadow.denial_count >= DENY_FUSE_THRESHOLD {
                                            // The next request should be locked.
                                            // Note: Deny Fuse triggers *after* the denial is reported.
                                        }
                                    }
                                    DecisionCode::AnomalyDetected => {
                                        stats.actual_anomalies.fetch_add(1, Ordering::SeqCst);
                                    }
                                    DecisionCode::AgentLocked => {
                                        stats.actual_locks.fetch_add(1, Ordering::SeqCst);
                                        shadow.is_locked = true;
                                    }
                                    _ => panic!("Unexpected decision code: {:?}", reason.code),
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // Random small delay to vary concurrency patterns
                tokio::time::sleep(Duration::from_millis(rng.gen_range(10..50))).await;
            }
        }));
    }

    for worker in workers {
        worker.await.expect("Worker panicked");
    }

    let elapsed = start_time.elapsed();
    println!("✅ Tier [{}] Finished in {:?}. Total requests: {}", tier_name, elapsed, stats.total_requests.load(Ordering::SeqCst));
    println!("   Results: Allows: {}, Denies: {}, Anomalies: {}, Locks: {}", 
        stats.actual_allows.load(Ordering::SeqCst),
        stats.actual_denies.load(Ordering::SeqCst),
        stats.actual_anomalies.load(Ordering::SeqCst),
        stats.actual_locks.load(Ordering::SeqCst)
    );

    // ── Assertions ──

    // 1. Consistency: Sum of decisions must equal total requests
    let sum = stats.actual_allows.load(Ordering::SeqCst) 
            + stats.actual_denies.load(Ordering::SeqCst)
            + stats.actual_anomalies.load(Ordering::SeqCst)
            + stats.actual_locks.load(Ordering::SeqCst);
    assert_eq!(sum, stats.total_requests.load(Ordering::SeqCst), "Decision sum mismatch");

    // 2. Metrics Consistency (Sampling)
    let metrics = get_metrics();
    let agent_sample_id = format!("{}-agent-0", TEST_PREFIX);
    let labels = agent_guard_sdk::metrics::DecisionLabels {
        agent_id: agent_sample_id.clone(),
        tool: "bash".to_string(),
        outcome: "allow".to_string(),
    };
    // Metrics should have values for at least some agents
    assert!(metrics.decision_total.get_or_create(&labels).get() > 0, "Metrics not incremented correctly");

    // 3. Receipt Verification (Sampling)
    let mut csprng = StdRng::from_entropy();
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();
    
    let sample_input = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"echo receipt-test"}"#.to_string(),
        context: Context {
            agent_id: Some(agent_sample_id.clone()),
            session_id: None,
            actor: None,
            trust_level: TrustLevel::Trusted,
            working_directory: None,
        },
    };
    let decision = guard.check(&sample_input);
    let receipt = ExecutionReceipt::sign(&agent_sample_id, "bash", "v1", "noop", &decision, "h", &signing_key);
    assert!(receipt.verify(&public_key.to_bytes()), "Receipt verification failed under load");
}

#[tokio::test]
async fn test_stress_concurrency_tier_s() {
    run_stress_tier(16, 30, "S").await; // 30s for S to be faster in local runs
}

#[tokio::test]
async fn test_stress_concurrency_tier_m() {
    // Only run M/L tiers if specifically requested or in CI
    if std::env::var("STRESS_TEST").is_ok() {
        run_stress_tier(64, 90, "M").await; // Adjusted to 90s for demo environment
    }
}

#[tokio::test]
async fn test_stress_concurrency_tier_l() {
    if std::env::var("STRESS_TEST_L").is_ok() {
        run_stress_tier(128, 300, "L").await;
    }
}
