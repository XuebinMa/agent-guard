# Observability Guide — agent-guard

`agent-guard` is designed to be a "monitorable" security infrastructure component. It provides structured audit logs, real-time metrics, and anomaly detection alerts.

---

## 1. 📊 Prometheus Metrics
The SDK exports real-time metrics via the `prometheus-client` registry.

### Metrics List
| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `agent_guard_policy_checks_total` | Counter | `tool`, `decision` | Total number of tool calls evaluated. Decisions: `allow`, `deny`, `ask`. |
| `agent_guard_execution_duration_seconds` | Histogram | `tool`, `sandbox_type` | Time taken to execute a tool in a sandbox. |
| `agent_guard_anomaly_triggered_total` | Counter | `tool` | Number of calls blocked by the frequency-based anomaly detector. |

### Labels Usage
- **`tool`**: The tool name (e.g., `bash`, `read_file`).
- **`decision`**: The outcome of the policy check.
- **`sandbox_type`**: The technology used for isolation (e.g., `linux-seccomp`, `macos-seatbelt`).

---

## 2. 🚨 Anomaly Detection Configuration
Anomaly detection prevents malicious or accidental "tool bombing" by limiting call frequency per actor.

### Configuration (`policy.yaml`)
```yaml
version: 1
default_mode: workspace_write

anomaly:
  enabled: true
  rate_limit:
    window_seconds: 60   # Sliding window size
    max_calls: 30        # Maximum allowed calls in the window
```

### Traceability
When an anomaly is triggered:
1. **Tracing**: A `WARN` level log is emitted via `tracing`.
2. **Metrics**: `agent_guard_anomaly_triggered_total` is incremented.
3. **Audit**: A structured JSONL record is written with `decision_code: "anomaly_detected"`.

---

## 3. 📜 Audit Logs (JSONL)
Audit logs provide the "ground truth" for security forensics.

### Sample Record
```json
{
  "type": "tool_call",
  "timestamp": "2026-04-07T04:06:54Z",
  "request_id": "cdd4e8f4...",
  "tool": "bash",
  "actor": "attacker",
  "decision": "deny",
  "decision_code": "anomaly_detected",
  "message": "anomaly detected: tool call frequency exceeded limit (30 calls / 60s)",
  "policy_version": "f95..."
}
```

### Connecting the Dots
1. **From Dashboard to Audit**: If you see a spike in `agent_guard_anomaly_triggered_total`, search your audit logs for `decision_code: "anomaly_detected"` to identify the offending `actor` and `tool`.
2. **From Audit to Policy**: Every audit record contains a `policy_version` (SHA-256 hash). Use this to verify which version of the policy was in effect at the time of the call.

---

## 4. 🛠️ Integration Guide

### Exporting to Prometheus (Rust)
```rust
use agent_guard_sdk::metrics::get_metrics;

// Access the registry to serve a /metrics endpoint
let mut body = String::new();
prometheus_client::encoding::text::encode(&mut body, &get_metrics().registry).unwrap();
```

### Initializing Tracing (Python)
```python
import agent_guard
# Enables internal tracing to capture security warnings
agent_guard.init_tracing()
```
