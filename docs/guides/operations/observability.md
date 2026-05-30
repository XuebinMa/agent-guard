# 📊 Observability & Monitoring

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | SREs, Security Analysts |
| **Version** | 1.2 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [Deployment Guide](deployment-guide.md), [Threat Model](../../concepts/threat-model.md) |

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
- `content_finding`: Content-layer detection on an executed call (opt-in `content` build). See below.

### Content findings (`content_finding`)

Emitted by the content layer when an executed call carries secrets / PII and the policy's `content.mode` is `mask` or `warn`. Requires a runtime built with the `content` feature; otherwise no such records are produced.

```json
{
  "type": "content_finding",
  "timestamp": "2026-05-29T12:00:00Z",
  "request_id": "5f1c…",
  "agent_id": "demo-agent",
  "tool": "write_file",
  "mode": "mask",
  "labels": ["AWS Access Key", "Email"],
  "count": 2
}
```

Notes:
- **No raw content.** The record carries only finding-*kind* labels (e.g. `AWS Access Key`, `Email`) and a `count` — never the matched secret/PII substring or the payload.
- **`mode`** is `mask` (the executed payload was redacted to `[REDACTED:<label>]`) or `warn` (executed unchanged). `block` does **not** emit this record — a blocked call is denied before execution and appears as a `tool_call` with decision `deny` and code `SENSITIVE_CONTENT_BLOCKED`.
- **Emitted on the execute path** (`Guard::execute` / `run`), not on a bare `Guard::check`. A check-only integration (e.g. the Claude Code hook) sees the `block` deny in `tool_call`, but not `content_finding` events.

---

## 3b. 🧾 Compliance Report (`guard-verify report`)

Turn an audit JSONL log into a control-evidence summary — what the boundary allowed vs denied, why, what the content layer caught, and under which policy versions — scoped to a window. This complements `guard-verify verify-log`, which cryptographically verifies signed execution receipts: the report answers *"what did the boundary do"*, the receipt log answers *"can we prove a specific execution happened"*.

```bash
# Human-readable summary over the last 7 days
guard-verify report --audit ~/.agent-guard/audit.jsonl --since 7d

# Machine/archival evidence (JSON), scoped to one agent
guard-verify report --audit audit.jsonl --since 30d --agent-id claude-code --format json
```

Flags: `--since` accepts `30s` / `5m` / `2h` / `7d` (omit for all records); `--agent-id` filters to one agent; `--format text|json`.

The report aggregates `tool_call` (decision counts, denials by code and by tool), `content_finding` (by mode and label), execution, `sandbox_failure`, and `anomaly_triggered` / `agent_locked` records, plus the distinct policy versions and agents observed. Malformed lines are counted (`parse_errors`) rather than aborting the run, so a partially-corrupt log still yields a report.

```text
=== agent-guard compliance report ===
generated:   2026-05-29T12:30:00+00:00
window:      7d
events span: 2026-05-29T11:00:00+00:00 .. 2026-05-29T11:04:00+00:00

records:     5 (1 parse error(s))
decisions:   3 tool_call · 1 allow · 2 deny · 0 ask
denials by code:
  DESTRUCTIVE_COMMAND              1
  SENSITIVE_CONTENT_BLOCKED        1
...
```

---

## 4. 🛠️ Configuration Checklist
- [ ] Set `audit.enabled: true` and `audit.output: file`.
- [ ] Expose `/metrics` endpoint using `agent_guard_sdk::get_metrics()`.
- [ ] Initialize `tracing-subscriber` with at least `INFO` level.
- [ ] **Verify platform-specific sandbox selection (execute_default) in startup logs.**

---

## 5. ⚙️ Audit File Backpressure

When `audit.output: file` is set, the SDK writes JSONL audit lines from a dedicated background thread fed by a bounded channel (capacity 1024). This keeps `writeln!` off the request hot path so concurrent tool calls do not serialize on a per-call file lock. Under sustained burst load that exceeds the channel capacity, the producer **drops the oldest excess events and emits a `tracing::warn!`** rather than blocking the request. This is a deliberate trade-off for an execution-control layer: blocking real tool calls so an audit line can flush would defeat the purpose. **The SIEM webhook is the durable export path; the local JSONL file is best-effort under sustained burst >1024 events.** Configure `audit.webhook_url` if you need lossless audit retention.
