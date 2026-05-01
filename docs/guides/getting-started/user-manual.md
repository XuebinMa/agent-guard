# 📖 User Manual

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | Developers, Integrators |
| **Version** | 1.2 |
| **Last Reviewed** | 2026-04-15 |
| **Related Docs** | [Migration Guide](migration-guide.md), [Threat Model](../../concepts/threat-model.md) |

---

Welcome to the official user manual for `agent-guard`. This guide will help you integrate, configure, and operate the execution control layer around agent side effects.

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

## 2. 🛡️ Configuring Your Execution Policy

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
use agent_guard_sdk::{Context, Guard, GuardInput, Tool};

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

### Current Execution Boundary

`agent-guard` supports two different enforcement layers today:

- **Policy gate for all supported tools**: `check()` and the adapter layers evaluate structured payloads against policy.
- **Sandboxed execution for shell / Bash**: `execute()` and adapter `enforce` mode are strongest on shell execution paths.

For non-shell tools such as `read_file`, `write_file`, `http_request`, and custom tool IDs, the current primary boundary is still `check` + policy evaluation unless your application provides an additional runtime boundary.

### Payload Contract

Use structured payloads consistently:

- `bash`: `{"command":"..."}`
- `read_file`: `{"path":"..."}`
- `write_file`: `{"path":"...","content":"..."}`
- `http_request`: `{"url":"..."}`
- custom tools: wrapper layers should normalize application input into a stable JSON object rather than relying on ad hoc string parsing

If you use the Node or Python wrappers, prefer letting the adapter normalize payload shape instead of building a separate string-munging layer in your app.

---

## 4. 📦 OS Sandboxes (The Final Barrier)

`agent-guard` automatically detects and selects the best sandbox for your platform. Run `cargo run -p guard-verify -- doctor --format text` to verify the host boundary you actually have. If you want a more narrative walkthrough for local exploration, `cargo run --example demo_transparency` is still a useful companion demo.

Important:

- a native backend can be compiled in but still be unavailable on the current host
- in those cases the SDK may explicitly fall back to `NoopSandbox`
- that fallback keeps the logic-layer policy gate, but it is **not** equivalent to OS-level isolation
- use `cargo run -p guard-verify -- doctor --format text` or the HTML report to confirm the real host boundary

---

## 📜 Verifiable Provenance (Signed Receipts)

Every execution can generate an Ed25519 signed receipt if a signing key is provided to the `Guard`. See the [Provenance Example](../../../crates/agent-guard-sdk/examples/provenance_receipt.rs) for details on how to set the key.

---

## 🏁 Best Practices

1. **Start with `read_only`**: Always default to the least privilege.
2. **Monitor the "Fuse"**: Set alerts for `AGENT_LOCKED` events.
3. **Automate CI/CD**: Run `cargo test --workspace --all-features` and `python3 scripts/check_docs.py` in your pipeline.
