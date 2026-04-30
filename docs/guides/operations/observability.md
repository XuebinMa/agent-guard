# 📊 Observability & Monitoring

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | SREs, Security Analysts |
| **Version** | 1.2 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [Deployment Guide](deployment-guide.md), [Threat Model](../../threat-model.md) |

---

This document describes how `agent-guard` integrates Audit Logs, Prometheus Metrics, and Tracing to provide a unified security monitoring framework.

---

## 1. 📂 Three Pillars of Observability

| Pillar | Technology | Purpose | Retention |
| :--- | :--- | :--- | :--- |
| **Audit Logs** | JSONL (Structured) | Forensic trail of every decision and outcome. | Long-term |
| **Metrics** | Prometheus | Real-time health and anomaly detection. | Mid-term |
| **Tracing** | `tracing` crate | Low-level SDK debugging. | Short-term |

---

## 🏗️ Security Boundaries (Observability)

| Category | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Audit** | Provides a structured record of all tool calls. | Audit logs themselves can be deleted if host OS is compromised. |
| **SIEM** | Pushes real-time alerts via Webhooks. | Alert fatigue if thresholds are set too low. |
| **Metrics** | Identifies abnormal patterns across 128+ concurrent agents. | Privacy of payload contents (Hashes only by default). |

---

## 2. 📊 Prometheus Metrics Reference

| Metric Name | Labels | Description |
| :--- | :--- | :--- |
| **`agent_guard_policy_checks_total`** | `agent_id`, `tool` | Total checks initiated. |
| **`agent_guard_decision_total`** | `agent_id`, `tool`, `outcome` | Decisions by outcome (`allow`, `deny`, `ask`). |
| **`agent_guard_anomaly_triggered_total`** | `agent_id`, `tool` | Anomalies detected and blocked. |
| **`agent_guard_execution_duration_seconds`** | `agent_id`, `tool`, `sandbox` | Execution latency distribution. |

---

## 3. 🌐 Webhook & SIEM Export

```yaml
audit:
  enabled: true
  webhook_url: "https://siem.example.com/ingest"
  include_payload_hash: true
```

### Supported Event Types
- `tool_call`: Detailed tool evaluation result.
- `execution_started` / `execution_finished`.
- `sandbox_failure`: Emitted on fail-closed errors.
- `anomaly_triggered` / `agent_locked`.

---

## 4. 🛠️ Configuration Checklist
- [ ] Set `audit.enabled: true` and `audit.output: file`.
- [ ] Expose `/metrics` endpoint using `agent_guard_sdk::get_metrics()`.
- [ ] Initialize `tracing-subscriber` with at least `INFO` level.
- [ ] **Verify platform-specific sandbox selection (execute_default) in startup logs.**

---

## 5. ⚙️ Audit File Backpressure

When `audit.output: file` is set, the SDK writes JSONL audit lines from a dedicated background thread fed by a bounded channel (capacity 1024). This keeps `writeln!` off the request hot path so concurrent tool calls do not serialize on a per-call file lock. Under sustained burst load that exceeds the channel capacity, the producer **drops the oldest excess events and emits a `tracing::warn!`** rather than blocking the request. This is a deliberate trade-off for an execution-control layer: blocking real tool calls so an audit line can flush would defeat the purpose. **The SIEM webhook is the durable export path; the local JSONL file is best-effort under sustained burst >1024 events.** Configure `audit.webhook_url` if you need lossless audit retention.
