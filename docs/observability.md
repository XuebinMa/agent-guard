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

## 2. 🔗 Correlation Map
To reconstruct a security event (e.g., an anomaly detection or a sandbox failure), correlate across these fields:

| Event Type | Audit Field (`audit.jsonl`) | Metric (`agent_guard_...`) | Tracing Level |
| :--- | :--- | :--- | :--- |
| **Policy Deny** | `decision: "deny"`, `code: "DENIED_BY_RULE"` | `decision_total{outcome="deny"}` | `INFO` |
| **Anomaly Triggered** | `decision: "deny"`, `code: "ANOMALY_DETECTED"` | `anomaly_triggered_total` | `WARN` |
| **Sandbox Execution** | `event: "tool_call"`, `stdout/stderr` | `execution_duration_seconds` | `DEBUG` |
| **Sandbox Failure** | `SandboxError` (in ExecuteResult) | N/A (Internal Error) | `ERROR` |
| **Policy Reload** | `event: "policy_reload"` | N/A | `INFO` |

---

## 3. 🚨 Security Runbook: Incident Response

### **Scenario A: High Anomaly Rate**
*   **Symptom**: `agent_guard_anomaly_triggered_total` spikes in Grafana.
*   **Action**: 
    1. Search `audit.jsonl` for `code: "ANOMALY_DETECTED"`.
    2. Identify the `actor` and `agent_id` involved.
    3. Review the last 10 tool calls from that actor to determine if it's a legitimate bot loop or a malicious attempt to bypass via volume.
    4. Adjust `anomaly.rate_limit` in `policy.yaml` if necessary.

### **Scenario B: Sandbox Fail-Closed**
*   **Symptom**: `Guard::execute()` returns a `SandboxError`.
*   **Action**:
    1. Check `tracing` logs at `ERROR` level.
    2. For Windows: Look for Win32 error codes (e.g., `CreateProcessAsUserW failed: 5 (Access is denied)`).
    3. For Linux: Check if `libseccomp` is correctly installed or if a specific syscall is being blocked that the tool requires.

### **Scenario C: Policy Bypass Attempt**
*   **Symptom**: `agent_guard_decision_total{outcome="deny"}` increases.
*   **Action**:
    1. Identify the matching rule using the `matched_rule` field in the audit log (e.g., `tools.bash.deny[0]`).
    2. Inspect the `payload_hash` and (if enabled) the raw payload to understand the attack vector.

---

## 4. 📊 Recommended Prometheus Alerts

```yaml
groups:
- name: AgentGuardAlerts
  rules:
  - alert: HighAnomalyRate
    expr: sum(rate(agent_guard_anomaly_triggered_total[1m])) > 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High frequency of anomalies detected for agent: {{ $labels.agent_id }}"

  - alert: PolicyDeniedSpike
    expr: sum(rate(agent_guard_decision_total{outcome="deny"}[5m])) > 5
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "Spike in denied tool calls detected."
```

---

## 5. 🛠️ Configuration Checklist
- [ ] Set `audit.enabled: true` and `audit.output: file`.
- [ ] Expose `/metrics` endpoint using the `Registry` from `agent_guard_sdk::metrics`.
- [ ] Initialize `tracing-subscriber` with at least `INFO` level.
