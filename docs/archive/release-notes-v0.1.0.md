# Phase 4 Release Notes: Telemetry & Windows Prototype

`agent-guard` version `0.1.0` (Phase 4) introduces cross-platform telemetry, anomaly detection, and an experimental Windows sandbox implementation.

## New Features

### 1. 📊 Telemetry & Metrics (M4.2)
The SDK now integrates `prometheus-client` to export security-relevant metrics.
- `agent_guard_decision_total`: Tracks `allow`, `deny`, and `ask` outcomes per tool.
- `agent_guard_execution_duration_seconds`: Histogram of sandbox execution latency.
- `agent_guard_anomaly_triggered_total`: Monitoring for frequency-based security blocks.

### 2. 🚨 Anomaly Detection (M4.3)
A new frequency-based detector is built into the `Guard::check()` flow.
- Configurable via the `anomaly:` block in your policy YAML.
- Prevents rapid-fire tool execution by a single actor.
- Triggers `ANOMALY_DETECTED` decisions with a full audit trail.

### 3. 🖥️ Windows Sandbox (M4.1)
An experimental prototype for Windows using **Job Objects**.
- Provides resource limits (CPU/Memory) and process tree management.
- Integrated into `Guard::execute_default()`.
- Note: This is an experimental filesystem-oriented prototype (not a full seccomp equivalent).

## 🚀 Migration Guide (Phase 3 -> Phase 4)

### Policy Update
If you are moving from a Phase 3 policy, you may want to add the new `anomaly` configuration:

```yaml
# Add this block to your policy.yaml
anomaly:
  enabled: true
  rate_limit:
    window_seconds: 60
    max_calls: 30
```

### SDK Integration (Rust)
The `Guard::check` and `Guard::execute` signatures have not changed, but you can now access the global registry for metrics:

```rust
use agent_guard_sdk::metrics::get_metrics;

// In your web server (e.g., axum, actix):
let mut body = String::new();
prometheus_client::encoding::text::encode(&mut body, &get_metrics().registry).unwrap();
```

### Logging
The SDK now uses the `tracing` crate. Ensure you have a subscriber (e.g., `tracing-subscriber`) initialized to see internal security warnings:

```rust
tracing_subscriber::fmt::init();
```
