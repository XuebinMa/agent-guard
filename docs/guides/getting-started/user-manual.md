# 📖 User Manual

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | Developers, Integrators |
| **Version** | 1.1 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [Migration Guide](migration-guide.md), [Threat Model](../../threat-model.md) |

---

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

## 🏗️ Security Boundaries (Logic Layer)

| Category | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Patterns** | Blocks shell redirections (`>`), piping (`|`), and known dangerous binaries. | Complex obfuscation that bypasses regex (Mitigated by OS Sandbox). |
| **Frequencies** | Prevents rapid-fire probing and DoS attacks via tool calls. | Stealthy, low-frequency attacks from multiple actors. |
| **Context** | Ensures per-agent settings are isolated via `agent_id`. | Misidentification if the host application sends wrong context IDs. |

---

## 3. 🏗️ Integrating with Your Code

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
```

---

## 4. 📦 OS Sandboxes (The Final Barrier)

`agent-guard` automatically detects and selects the best sandbox for your platform. Run `cargo run --example demo_transparency` to verify.

---

## 5. 🔍 Monitoring & SIEM

All decisions are logged to `audit.jsonl`. You can also configure Webhooks for real-time SIEM integration. See the **[Observability Guide](../operations/observability.md)**.

---

## 📜 Verifiable Provenance (Signed Receipts)

Every execution generates an Ed25519 signed receipt. See the [Provenance Example](../../../crates/agent-guard-sdk/examples/provenance_receipt.rs) for details.

---

## 🏁 Best Practices

1. **Start with `read_only`**: Always default to the least privilege.
2. **Monitor the "Fuse"**: Set alerts for `AGENT_LOCKED` events.
3. **Automate CI/CD**: Run `cargo test --test release_gate` in your pipeline.
