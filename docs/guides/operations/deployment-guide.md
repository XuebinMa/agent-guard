# 🚀 Production Deployment Guide

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | DevOps, SREs, System Admins |
| **Version** | 1.1 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [Observability](observability.md), [Capability Parity](../../capability-parity.md) |

---

This guide provides best practices and operational procedures for deploying `agent-guard` in production environments.

---

## 1. 🏗️ Recommended Deployment Architecture

For most enterprise use cases, we recommend the following sidecar or host-agent architecture:

1. **Host Application**: Your AI Agent framework (e.g., built with LangChain, Autogen, or custom Rust/Node.js).
2. **agent-guard SDK**: Integrated into the host application to intercept tool calls.
3. **OS Sandboxes**:
   - **Linux**: Seccomp-BPF (Production Ready).
   - **Windows**: Low-IL (Strengthened Prototype - Default) or **AppContainer** (Experimental - Opt-in).
   - **macOS**: Seatbelt (Internal Prototype).

---

## 🏗️ Security Boundaries (Operational)

| Platform | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Containers** | Seccomp syscall filtering inside Docker/K8s. | Kernel vulnerabilities (LPE). |
| **Permissions** | Prevents agents from writing to host `/etc` or `C:\Windows`. | Global read access on macOS/Windows (Prototype limit). |
| **Reliability** | Fail-closed: The system stops if the security environment is unstable. | Downtime caused by missing system dependencies (e.g., `libseccomp`). |

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
  file_path: "/var/log/agent-guard/audit.jsonl"
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

---

## 4. 🚨 Webhook Runbook: Handling Incidents

When a `webhook_url` is configured, `agent-guard` pushes real-time `AuditRecord` objects.

### Incident: `AGENT_LOCKED` (Deny Fuse)
- **Description**: An agent has been locked because it triggered too many security denials.
- **Action**: Query `audit.jsonl` for the agent's recent history and reset the service if it's a false positive.

### Incident: `sandbox_failure`
- **Description**: The sandbox failed to initialize or execute.
- **Action**: Check Win32/Linux error codes in logs and verify system permissions.

---

## 5. 🔄 Continuous Improvement

- **Audit Review**: Periodically review `/var/log/agent-guard/audit.jsonl`.
- **Fail-Closed Verification**: Periodically attempt an unauthorized tool call to ensure the Guard is active.
