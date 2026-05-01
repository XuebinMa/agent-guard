# 🚀 Production Deployment Guide

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | DevOps, SREs, System Admins |
| **Version** | 1.1 |
| **Last Reviewed** | 2026-04-15 |
| **Related Docs** | [Observability](observability.md), [Capability Parity](../../concepts/capability-parity.md) |

---

This guide provides best practices and operational procedures for deploying `agent-guard` in production environments.

---

## 1. 🏗️ Recommended Deployment Architecture

For most production deployments with real side effects, we recommend the following sidecar or host-agent architecture:

1. **Host Application**: Your AI Agent framework (e.g., built with LangChain-style tools, OpenAI-style handlers, or a custom Rust/Node/Python runtime).
2. **agent-guard SDK**: Integrated into the host application to intercept tool calls.
3. **OS Sandboxes**:
   - **Linux**: Native Seccomp-BPF filtering when the `seccomp` feature is enabled; Landlock can add stronger path-aware filesystem isolation where supported.
   - **Windows**: Low-IL (Strengthened Prototype - Default) or **AppContainer** (Experimental - Opt-in).
   - **macOS**: Seatbelt (Internal Prototype).

---

## 🏗️ Security Boundaries (Operational)

| Platform | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Containers** | Deployment-level isolation you configure separately (e.g. Docker/K8s profiles). | `agent-guard` seccomp is syscall-oriented; container profiles are still responsible for broader host isolation. |
| **Permissions** | Prevents agents from writing to host `/etc` or `C:\Windows`. | Global read access on macOS/Windows (Prototype limit). |
| **Reliability** | Fail-closed: The system stops if the security environment is unstable. | Downtime caused by missing system dependencies (e.g., `libseccomp`). |

---

## 2. 🛡️ Hardening your Policy (`policy.yaml`)

Never deploy with `default_mode: full_access`.

### Base Security Template
```yaml
version: 1
default_mode: read_only

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

Set the per-execution workspace in the host `Context` (for example `Context.working_directory` in Rust), not as a top-level policy key.

---

## 3. 🏥 Pre-flight Check: Capability Doctor

Before going live, run the `CapabilityDoctor` on your production nodes to ensure the intended sandboxes are functional.

```bash
# Verify available security features
cargo run -p guard-verify -- doctor --format text
```

Check for these signals before rollout:
- The reported `Default SDK sandbox` should match the backend you expect to rely on in production.
- `Fallback: Yes` means the SDK is explicitly using `NoopSandbox`; treat that as a deployment blocker if you expected OS-level isolation.
- Shell / Bash is the strongest current `enforce` path. For non-shell tools, do not treat a green doctor report as proof that every tool type now has equivalent runtime isolation.
- On Windows, inspect the runtime checks individually to distinguish token creation support, Job Object support, and low-integrity process launch support.

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
