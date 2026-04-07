# Observability Linkage — agent-guard

> Status: **Phase 5 (Active)**  
> This document describes how `agent-guard` integrates Audit Logs, Prometheus Metrics, and Tracing to provide a unified security monitoring and incident response (IR) framework.

---

## 1. 📂 Three Pillars of Observability

| Pillar | Technology | Purpose | Retention |
| :--- | :--- | :--- | :--- |
| **Audit Logs** | JSONL (Structured) | Detailed forensic trail of every decision, tool call, and sandbox outcome. | Long-term (Archive) |
| **Metrics** | Prometheus / OpenTelemetry | Real-time health monitoring, anomaly detection, and capacity planning. | Mid-term (Aggregated) |
| **Tracing** | `tracing` crate (Log-level) | Low-level debugging of internal SDK logic, policy parsing, and Win32/Seccomp setup. | Short-term (Ephemeral) |

---

## 2. 📊 Prometheus Metrics Reference

`agent-guard` exposes high-level metrics via the `prometheus-client` registry.

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| **`agent_guard_policy_checks_total`** | Counter | `agent_id`, `tool` | Total number of policy checks initiated. |
| **`agent_guard_decision_total`** | Counter | `agent_id`, `tool`, `outcome` | Total decisions by outcome (`allow`, `deny`, `ask`). |
| **`agent_guard_anomaly_triggered_total`** | Counter | `agent_id`, `tool` | Total number of anomalies detected and blocked. |
| **`agent_guard_execution_duration_seconds`** | Histogram | `agent_id`, `tool`, `sandbox_type` | Latency distribution of tool execution in sandboxes. |

### Accessing the Registry
In your host application, use the `get_metrics()` helper to access the global registry:

```rust
use agent_guard_sdk::get_metrics;
let metrics = get_metrics();
// Expose metrics.registry via your preferred HTTP server (Axum, Actix, etc.)
```

---

## 3. 🛠️ Implementation Examples

### Exposing `/metrics` with Axum
```rust
use axum::{routing::get, Router, response::IntoResponse};
use prometheus_client::encoding::text::encode;
use agent_guard_sdk::get_metrics;

async fn metrics_handler() -> impl IntoResponse {
    let metrics = get_metrics();
    let mut buffer = String::new();
    // Encode the global registry into Prometheus text format
    if encode(&mut buffer, &metrics.registry).is_ok() {
        buffer
    } else {
        "Internal Error".to_string()
    }
}

// In your router setup:
let app = Router::new().route("/metrics", get(metrics_handler));
```

---

## 4. 🔗 Correlation Map
To reconstruct a security event, correlate across these fields:

| Event Type | Audit Field (`audit.jsonl`) | Metric (`agent_guard_...`) | Tracing Level |
| :--- | :--- | :--- | :--- |
| **Policy Deny** | `decision: "deny"`, `code: "DENIED_BY_RULE"` | `decision_total{outcome="deny"}` | `INFO` |
| **Anomaly Triggered** | `decision: "deny"`, `code: "ANOMALY_DETECTED"` | `anomaly_triggered_total` | `WARN` |
| **Agent Locked** | `decision: "deny"`, `code: "AGENT_LOCKED"` | `anomaly_triggered_total` | `ERROR` |
| **Sandbox Execution** | `event: "tool_call"`, `stdout/stderr` | `execution_duration_seconds` | `DEBUG` |
| **Sandbox Failure** | `SandboxError` (in ExecuteResult) | N/A (Internal Error) | `ERROR` |
| **Policy Reload** | `event: "policy_reload"` | N/A | `INFO` |

---

## 5. 🚨 Recommended Prometheus Alerts

```yaml
groups:
- name: AgentGuardAlerts
  rules:
  - alert: HighAnomalyRate
    # Alert if any specific agent exceeds 1 anomaly detection per second.
    expr: sum by (agent_id) (rate(agent_guard_anomaly_triggered_total[1m])) > 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High frequency of anomalies detected for agent: {{ $labels.agent_id }}"

  - alert: PolicyDeniedSpike
    # Alert if any agent is hitting many rule-based denials.
    expr: sum by (agent_id) (rate(agent_guard_decision_total{outcome="deny"}[5m])) > 5
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "Spike in denied tool calls for agent: {{ $labels.agent_id }}"
```

---

## 6. 🚨 Security Runbook: Incident Response

### **Scenario A: High Anomaly Rate**
*   **Symptom**: `agent_guard_anomaly_triggered_total` spikes in Grafana.
*   **Action**: 
    1. Search `audit.jsonl` for `code: "ANOMALY_DETECTED"`.
    2. Identify the `actor` and `agent_id` involved from the labels.
    3. Review the last 10 tool calls from that actor to determine if it's a legitimate bot loop or a malicious attempt to bypass via volume.
    4. Adjust `anomaly.rate_limit` in `policy.yaml` if necessary.

### **Scenario B: Agent Locked (Deny Fuse)**
*   **Symptom**: `agent_guard_decision_total{outcome="deny"}` for a specific agent stays at 100% of calls, and audit logs show `code: "AGENT_LOCKED"`.
*   **Action**:
    1. This indicates the agent triggered too many rule-based denials (e.g., trying to access forbidden files) and has been automatically "fused" (locked).
    2. Review the `audit.jsonl` history for that agent to see the preceding denials that triggered the fuse.
    3. If the agent's behavior is corrected, restart the host application to reset the in-memory fuse (or use a management API if implemented).
    4. Adjust `anomaly.deny_fuse` settings in `policy.yaml` if the threshold is too sensitive.

### **Scenario C: Sandbox Fail-Closed**

---

## 7. 🛠️ Configuration Checklist
- [ ] Set `audit.enabled: true` and `audit.output: file`.
- [ ] Expose `/metrics` endpoint using `agent_guard_sdk::get_metrics()`.
- [ ] Initialize `tracing-subscriber` with at least `INFO` level.
