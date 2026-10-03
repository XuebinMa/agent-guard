# 📊 Observability & Monitoring

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | SREs, Security Analysts |
| **Version** | 1.3 |
| **Last Reviewed** | 2026-10-01 |
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
- `execution_started` / `execution_finished`: executions the Guard witnessed.
- `execution_reported`: a host-transcribed handoff outcome (see below).
- `sandbox_failure`: Emitted on fail-closed errors.
- `anomaly_triggered` / `agent_locked`.
- `content_finding`: Content-layer detection on an executed call (opt-in `content` build). See below.
- `policy_reload`: Successful or failed policy replacement.

One `Guard::run` evaluation owns one `request_id` and one immutable policy
snapshot. Its `tool_call`, `execution_started`, and terminal
`execution_finished`, `sandbox_failure`, or host-supplied
`execution_reported` records reuse that ID. The same serialized records are
fanned out to the configured local destination (file or stdout/custom sink)
and the SIEM exporter; `audit.enabled: false` disables the complete stream.
It does not disable one-shot handoff request tracking: a valid report is still
consumed once (without emitting a record), while unknown, expired, and duplicate
IDs are rejected. This audit-disabled compatibility registry is bounded at
4,096 pending IDs: on overflow it evicts the oldest audit-disabled entry, so a
host that leaves thousands of handoffs outstanding must treat a later
``unknown request`` error as a lost lifecycle rather than retrying the action.
Audited pending handoffs are never evicted to make room for unaudited ones.
`anomaly_triggered` and `agent_locked` also carry the request ID that produced
the verdict; readers must tolerate its absence in records written by older
versions.

### Host-reported handoff outcomes (`execution_reported`)

When `Guard::run` returns a `Handoff`, it first emits
`execution_started` with `sandbox_type: "host-handoff"`. The host then executes
the action itself and reports the outcome via `Guard::report_handoff_result`
using the returned `request_id`. The Guard did not observe that execution, so
the terminal record is transcribed rather than witnessed. The reported record
retains the original tool and agent identity and carries
`sandbox_type: "host-handoff"`. The request ID is one-shot: an unknown,
expired, or already-reported handoff is rejected by
`Guard::try_report_handoff_result` rather than creating an orphan terminal
record. Pending handoffs also retain the original audit destinations across a
policy reload. If a host action succeeds but its terminal report fails, the
Python and Node adapters surface an execution error instead of returning an
apparently complete lifecycle. That error says the action already completed,
carries the host result, and warns callers not to retry automatically. If the host action itself failed, its original
exception remains primary and carries the report failure as secondary context.

```json
{
  "type": "execution_reported",
  "timestamp": "2026-08-19T12:00:00Z",
  "request_id": "5f1c…",
  "tool": "read_file",
  "sandbox_type": "host-handoff",
  "duration_ms": 42,
  "exit_code": 0
}
```

> **Migration note (wire-format break, pre-1.0):** handoff outcomes previously
> emitted `type: "execution_finished"`. A consumer of the audit JSONL or SIEM
> stream matching only `execution_finished` will *silently* stop seeing handoff
> records — they now arrive as `execution_reported`. Update matchers to handle
> both types. `execution_finished` is now reserved for executions the Guard
> itself performed and is unchanged for those. Treat an unrecognized `type`
> value as a signal to update the consumer, not as noise to drop.
>
> Handoff reports emitted before this hardening used the synthetic tool value
> `handoff` and no agent ID. Consumers should now accept the original tool and
> agent copied from the correlated `execution_started` record.

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
