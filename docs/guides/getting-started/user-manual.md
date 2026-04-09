# 📖 User Manual

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | Developers, Integrators |
| **Version** | 1.2 |
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
Available now in `crates/agent-guard-python` and `crates/agent-guard-node`. Build from source using `maturin` (Python) or `npm install`.

---

## 2. 🛡️ Configuring Your Security Policy

The heart of `agent-guard` is the `policy.yaml` file.

### Basic Structure
```yaml
version: 1
default_mode: read_only

# Tool-specific rules
tools:
  bash:
    allow:
      - "ls"
    deny:
      - "rm -rf /"
    mode: workspace_write

# Proactive Defense
anomaly:
  enabled: true
  rate_limit:
    max_calls: 30
    window_seconds: 60
  deny_fuse:
    enabled: true
    threshold: 5
```

---

## 🏗️ Security Boundaries (Logic Layer)

| Category | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Filesystem** | Prevents unauthorized writes to system directories. | Global read access on some platforms (See Parity Matrix). |
| **Execution** | Blocks shell redirections and known dangerous binaries. | Complex shell obfuscation (Mitigated by OS Sandbox). |

---

## 3. 🏗️ Integrating with Your Code

```rust
use agent_guard_sdk::{Guard, Context, Tool};

// 1. Load Guard
let guard = Guard::from_yaml_file("policy.yaml")?;

// 2. Prepare Context
let context = Context {
    agent_id: Some("researcher-bot".into()),
    actor: Some("user-123".into()),
    working_directory: Some("/tmp/agent-work".into()),
    ..Default::default()
};

// 3. Secure Execution
let result = guard.execute_default(&GuardInput {
    tool: Tool::Bash,
    payload: r#"{"command":"ls"}"#.to_string(),
    context,
})?;
```

---

## 4. 📦 OS Sandboxes (The Final Barrier)

`agent-guard` automatically detects and selects the best sandbox for your platform. Run `cargo run --example demo_transparency` to verify.

---

## 📜 Verifiable Provenance (Signed Receipts)

Every execution can generate an Ed25519 signed receipt if a signing key is provided to the `Guard`. See the [Provenance Example](../../../crates/agent-guard-sdk/examples/provenance_receipt.rs) for details on how to set the key.

---

## 🏁 Best Practices

1. **Start with `read_only`**: Always default to the least privilege.
2. **Monitor the "Fuse"**: Set alerts for `AGENT_LOCKED` events.
3. **Automate CI/CD**: Run `cargo test --test release_gate` in your pipeline.
