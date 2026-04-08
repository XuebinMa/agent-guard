# 🛡️ agent-guard

> **End-to-end security barrier for AI agents.**  
> **Intercept tool calls, evaluate against policies, and execute in hardened sandboxes.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Phase](https://img.shields.io/badge/Phase-7%20Complete-green.svg)]()
[![Build Status](https://github.com/XuebinMa/agent-guard/actions/workflows/rust.yml/badge.svg)](https://github.com/XuebinMa/agent-guard/actions)

---

### 💡 Why agent-guard?

When Large Language Models (LLMs) are granted **Tool Use** or **Function Calling** capabilities, they effectively gain operating system privileges. **Prompt Injection** attacks can trick models into executing destructive commands like `rm -rf /` or performing unauthorized internal network scans.

`agent-guard` acts as an **independent security enforcement layer** between the LLM orchestrator and the host system:

- **Semantic Validation**: Intercept tool arguments and validate them against declarative policies using a restricted DSL (`evalexpr`).
- **Environment Isolation**: Mandatory process sandboxing using **Linux Seccomp-BPF**, **macOS Seatbelt**, and **Windows Job Objects**.
- **Audit & Observability**: Structured, non-repudiable JSONL logs and **Prometheus metrics** (`policy_checks_total`, `execution_duration_seconds`).
- **Anomaly Detection**: Built-in rate limiting and frequency-based detection to prevent accidental or malicious destructive loops.

---

### ✨ Key Features

- 🦀 **High Performance**: Built in Rust for sub-millisecond interception latency and memory safety.
- 📜 **Declarative Policy**: Simple YAML configuration supporting regex, path globbing, and context-aware variables (e.g., `actor`, `agent_id`).
- 🔄 **Atomic Hot-Reload**: Update policies on the fly with single-request snapshot isolation using `ArcSwap`.
- 🌍 **Multi-Language Ecosystem**:
  - **Node.js**: High-performance bindings via `napi-rs` with full TypeScript definitions.
  - **Python**: Deep integration with **LangChain 0.3** and native observability support.
- 🛡️ **Cross-Platform Sandboxing**:
  - **Linux**: Production-grade `Seccomp-BPF` syscall filtering.
  - **macOS**: `sandbox-exec` (Seatbelt) for filesystem isolation.
  - **Windows**: **Low-IL Enforcement** (default) and **AppContainer Prototype** (opt-in) for object-level isolation.

---

### 📺 Security Demos

- **Demo 1: Happy Path** - Standard execution + audit + verifiable receipt.
  - `cargo run --example demo_happy_path`
- **Demo 2: Malicious Block** - Proactive defense via Deny Fuse.
  - `cargo run --example demo_malicious_block`
- **Demo 3: Transparency** - Real-time host capability report (UCM).
  - `cargo run --example demo_transparency`
- **Demo 4: The Comparison** - Comparison of security tiers (No Guard vs. Full Guard).
  - `cargo run --example demo_comparison`

---

### 🏥 Adoption & Migration

- **Capability Doctor**: Use the `CapabilityDoctor` to detect and report on the host's security features.
  - `cargo run --example doctor`
- **Migration Guide**: Read the [Migration Guide](docs/migration-guide.md) to transition from development to production-ready sandboxes.

---

### 🚀 Quick Start

#### Node.js / TypeScript
```typescript
import { Guard } from '@agent-guard/node';

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
anomaly:
  enabled: true
  rate_limit: { window_seconds: 60, max_calls: 30 }
`);

// Evaluate and execute in one call (automatically selects the best sandbox)
const outcome = await guard.execute('bash', JSON.stringify({ command: 'ls -la' }));
if (outcome.outcome === 'executed') {
  console.log(outcome.output.stdout);
}
```

#### Rust SDK
```rust
use agent_guard_sdk::{Guard, Tool, GuardInput, ExecuteOutcome};

let guard = Guard::from_yaml_file("policy.yaml")?;
let input = GuardInput::new(agent_guard_core::Tool::Bash, r#"{"command":"ls"}"#);

// Automatically chooses the best sandbox (Linux: Seccomp, macOS: Seatbelt, Windows: JobObject)
match guard.execute_default(&input) {
    Ok(ExecuteOutcome::Executed { output }) => println!("stdout: {}", output.stdout),
    Ok(ExecuteOutcome::Denied { reason }) => eprintln!("Blocked: {}", reason.message),
    _ => {}
}
```

---

### 📊 Platform Capability Matrix

| Security Feature | Linux (Seccomp) | macOS (Seatbelt) | Windows (Low-IL) | Windows (AppContainer) |
| :--- | :---: | :---: | :---: | :---: |
| **Policy Enforcement** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Syscall Filtering** | ✅ BPF | ❌ N/A | ❌ N/A | ❌ N/A |
| **Filesystem Isolation** | ✅ Strict | 🟡 Experimental | ✅ **Low-IL** | ✅ **SID-Based** |
| **Network Blocking** | ✅ Strict | ✅ Strict | ❌ Planned | ✅ **Restricted** |
| **Resource Limits** | ✅ Native | ❌ N/A | ✅ Verifiable | ✅ Verifiable |
| **Anomaly Detection** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Telemetry & SIEM** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |

> **Security Note**: Windows AppContainer is currently an **experimental prototype** (opt-in). Linux Seccomp-BPF is the recommended choice for high-security production environments. See [docs/capability-parity.md](docs/capability-parity.md) for detailed comparisons.

---

### 🗺️ Roadmap

- [x] **Phase 1-4**: Core Engine, Linux Sandbox, Telemetry, Anomaly Detection.
- [x] **Phase 5**: Windows Low-IL Enforcement, Threat Model v2 (STRIDE).
- [x] **Phase 6**: Enterprise Security: Unified Capability Model (UCM), Signed Receipts, SIEM (Webhook).
- [x] **Phase 7**: Production Hardening, Cross-platform Parity Tests, AppContainer Prototype.
- [x] **Phase 8**: v0.2.0 RC Validation: E2E Test Matrix, Public Demo Pack.
- [ ] **Phase 9 (v0.3.0)**: TPM-backed Remote Attestation, Linux Landlock/Namespaces integration, OTLP SIEM exporter.

---

### 🤝 Contributing & Feedback

If you find this project useful, please give it a ⭐️ **Star**! It helps the project grow.

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/XuebinMa/agent-guard/issues).
- **Security Audit**: See [docs/threat-model.md](docs/threat-model.md) for current security boundaries.
- **Vulnerabilities**: Please report security vulnerabilities privately.

---
**License**: MIT | Built with 🦀 for a safer AI future.
