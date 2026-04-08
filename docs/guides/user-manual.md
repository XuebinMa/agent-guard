# 📖 agent-guard User Manual (v0.2.0)

Welcome to the official user manual for `agent-guard`. This guide will help you integrate, configure, and operate the ultimate security layer for your AI Agents.

---

## 1. 🚀 Quick Start & Installation

`agent-guard` is designed to be integrated directly into your AI host application.

### Rust SDK
Add the dependency to your `Cargo.toml`:
```toml
[dependencies]
agent-guard-sdk = { git = "https://github.com/XuebinMa/agent-guard" }
```

### Python/Node.js Bindings
*Coming soon!* (Pre-release binaries available in `crates/agent-guard-python` and `crates/agent-guard-node`).

---

## 2. 🛡️ Configuring Your Security Policy

The heart of `agent-guard` is the `policy.yaml` file. It defines what your agents can and cannot do.

### Basic Structure
```yaml
version: 1
default_mode: read_only  # Default: blocked, read_only, workspace_write, full_access

# Global restrictions
working_directory: "/path/to/safe/workspace"

# Tool-specific rules
tools:
  bash:
    allow:
      - "ls"
      - "cat *.txt"
    deny:
      - "rm -rf /"
      - "curl http://hacker.com"
    mode: workspace_write # Override default for this tool

# Proactive Defense
anomaly:
  enabled: true
  rate_limit:
    max_calls: 30
    window_seconds: 60
  deny_fuse:
    enabled: true
    threshold: 5 # Lock agent after 5 denials
```

---

## 3. 🏗️ Integrating with Your Code

### Basic Execution Flow
1. **Initialize**: Load your policy.
2. **Check**: Intercept the tool call and validate against the policy.
3. **Execute**: Run the command in a hardened OS sandbox.

```rust
use agent_guard_sdk::{Guard, Context, Tool};

// 1. Load Guard
let guard = Guard::from_file("policy.yaml")?;

// 2. Prepare Context
let context = Context {
    agent_id: Some("researcher-bot".into()),
    actor: Some("user-123".into()),
    ..Default::default()
};

// 3. Secure Execution
let result = guard.check_tool(Tool::Bash, r#"{"command":"ls"}"#, context);
// ... handle decision and execute in sandbox
```

---

## 4. 📦 OS Sandboxes (The Final Barrier)

`agent-guard` automatically detects and selects the best sandbox for your platform:

| Platform | Sandbox Technology | Capability |
| :--- | :--- | :--- |
| **Linux** | `Seccomp-BPF` | **Production Ready**: Kernel-level syscall blocking. |
| **Windows** | `Low-IL` / `Job Object` | **Strengthened**: Prevents system directory writes. |
| **macOS** | `Seatbelt` | **Active**: Filesystem isolation via `sandbox-exec`. |

**Verify your environment**:
Run `cargo run --example demo_transparency` to see exactly what your host supports.

---

## 5. 🔍 Monitoring & SIEM

### Audit Logs
All decisions are logged to `audit.jsonl` by default. Use this for forensic analysis.

### Metrics (Prometheus)
Expose the `/metrics` endpoint to monitor:
- `agent_guard_decision_total`: Total allows/denials.
- `agent_guard_anomaly_triggered_total`: Frequency violations.
- `agent_guard_execution_duration_seconds`: Performance tracking.

### Webhook Export
Push security events in real-time to your SIEM (Slack, PagerDuty, etc.). See the [Observability Guide](observability.md) for details.
```yaml
audit:
  webhook_url: "https://your-webhook.endpoint"
```

---

## 6. 📜 Verifiable Provenance (Signed Receipts)

`agent-guard` provides cryptographic proof of execution. This is essential for zero-trust architectures.

1. Generate a receipt after execution.
2. The receipt includes the policy version, command hash, and sandbox type.
3. Sign it with an Ed25519 key.
4. Verify it later to ensure the execution context hasn't been tampered with.

See the [Signed Receipts Example](../../crates/agent-guard-sdk/examples/provenance_receipt.rs) for implementation details.

---

## 🏥 Diagnostics: The Capability Doctor

If you're unsure why a sandbox isn't working, use the built-in doctor:
```bash
cargo run --example demo_transparency
```
It will report on:
- Sandbox availability.
- Health status (execution check).
- UCM Capability Matrix (see [Capability Parity Matrix](../capability-parity.md)).

---

## 🚀 Deployment & Operations

For production environments, please consult our specialized guides:
- [Production Deployment Guide](deployment-guide.md)
- [Migration Guide](migration-guide.md)
- [Observability & Monitoring](observability.md)

---

## 🏁 Best Practices

1. **Start with `read_only`**: Always default to the least privilege.
2. **Use Dedicated Workspaces**: Ensure `working_directory` is strictly controlled.
3. **Monitor the "Fuse"**: Set alerts for `AGENT_LOCKED` events—they usually indicate an active attack.
4. **Automate CI/CD**: Run `cargo test --test release_gate` in your pipeline to ensure security invariants are never broken.
