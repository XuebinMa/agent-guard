# Production Deployment Guide — agent-guard

> Status: **Draft (Phase 7)**  
> Version: **1.0**  
> This guide provides best practices and operational procedures for deploying `agent-guard` in production environments.

---

## 1. 🏗️ Recommended Deployment Architecture

For most enterprise use cases, we recommend the following sidecar or host-agent architecture:

1. **Host Application**: Your AI Agent framework (e.g., built with LangChain, Autogen, or custom Rust/Node.js).
2. **agent-guard SDK**: Integrated into the host application to intercept tool calls.
3. **OS Sandboxes**:
   - **Linux**: Seccomp-BPF (Production Ready).
   - **Windows**: Low-IL (Strengthened Prototype - Default) or **AppContainer** (Experimental - Opt-in).
   - **macOS**: Seatbelt (Internal Prototype).
4. **SIEM / Observability Stack**: Grafana, Prometheus, and a Webhook listener.

---

## 2. 🛡️ Hardening your Policy (`policy.yaml`)

Never deploy with `default_mode: full_access`.

### Base Security Template
```yaml
version: 1
default_mode: read_only

# Restricted workspace for each agent session
working_directory: "/var/lib/agent-workspace"

audit:
  enabled: true
  output: "file"
  path: "/var/log/agent-guard/audit.jsonl"
  webhook_url: "https://your-siem-webhook.internal/ingest"

anomaly:
  enabled: true
  rate_limit:
    max_calls: 20
    window_seconds: 60
  deny_fuse:
    enabled: true
    threshold: 5
```

---

## 3. 🏥 Pre-flight Check: Capability Doctor

Before going live, run the `CapabilityDoctor` on your production nodes to ensure the intended sandboxes are functional.

```bash
# Verify available security features
cargo run --example doctor
```

**Verify the checklist:**
- [ ] Sandbox Health: `✅ PASS`
- [ ] FS Isolation: `Yes` (Required for Windows/macOS)
- [ ] Syscall Filtering: `Yes` (Required for Linux)

---

## 4. 🚨 Webhook Runbook: Handling Incidents

When a `webhook_url` is configured, `agent-guard` pushes real-time `AuditRecord` objects.

### Incident: `AGENT_LOCKED` (Deny Fuse)
- **Description**: An agent has been locked because it triggered too many security denials.
- **Action**:
  1. Inspect the JSON payload from the Webhook.
  2. Locate the `agent_id` and `actor`.
  3. Query the `audit.jsonl` for the specific sequence of denied commands.
  4. If it was a false positive, adjust the `policy.yaml` rules or `deny_fuse.threshold`.
  5. Restart the service to reset the in-memory fuse.

### Incident: `sandbox_failure`
- **Description**: The sandbox failed to initialize or execute.
- **Action**:
  1. Check the `error` field in the Webhook payload.
  2. Verify OS permissions (e.g., is the process running as a user with sufficient Win32 privileges for Low-IL?).
  3. Verify disk space and working directory existence.

---

## 5. 📊 SIEM Integration (Grafana/Prometheus)

1. **Import Metrics**: Ensure your host application exposes the `/metrics` endpoint (see [Observability Guide](observability.md)).
2. **Dashboard**: Use the `agent_id` label to create per-agent performance and security views.
3. **Alerts**: Configure alerts for `agent_guard_anomaly_triggered_total` spikes.

---

## 6. 🔄 Continuous Improvement

- **Audit Review**: Periodically review `/var/log/agent-guard/audit.jsonl` to discover new patterns of tool usage.
- **Version Pinning**: Use the `receipt_version` from Signed Receipts to ensure your downstream auditors are processing data correctly.
- **Fail-Closed Verification**: Periodically attempt an unauthorized tool call to ensure the Guard is still active and blocking.
