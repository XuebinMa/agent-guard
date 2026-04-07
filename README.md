# 🛡️ agent-guard

> **End-to-end security barrier for AI agents.**  
> **Intercept tool calls, evaluate against policies, and execute in hardened sandboxes.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/Version-0.1.0--alpha-blue.svg)]()
[![Phase](https://img.shields.io/badge/Phase-4%20v1%20Complete-green.svg)]()
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
  - **macOS**: Experimental prototype (`SeatbeltSandbox`) for filesystem isolation.
  - **Windows**: Experimental prototype (`JobObjectSandbox`) for resource and process management.

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

| Security Feature | Linux (Seccomp) | macOS (Seatbelt) | Windows (Job Object) |
| :--- | :---: | :---: | :---: |
| **Policy Enforcement** | ✅ Full | ✅ Full | ✅ Full |
| **Syscall Filtering** | ✅ BPF | ❌ N/A | ❌ N/A |
| **Filesystem Isolation** | ✅ Strict | 🟡 Experimental | ❌ Planned |
| **Resource Limits** | ✅ Native | ❌ N/A | ✅ Experimental |
| **Anomaly Detection** | ✅ Full | ✅ Full | ✅ Full |
| **Telemetry (Prometheus)** | ✅ Full | ✅ Full | ✅ Full |

> **Security Note**: macOS and Windows implementations are currently **experimental prototypes**. While they provide valuable isolation, they do not yet match the syscall-level hardening provided by Seccomp on Linux. See [docs/threat-model.md](docs/threat-model.md) for detailed boundaries.

---

### 🗺️ Roadmap

- [x] **Phase 1-2**: Core Engine, Linux Sandbox, Python Bindings.
- [x] **Phase 3**: Node.js Bindings, Atomic Reloading, Policy DSL.
- [x] **Phase 4**: Telemetry (Prometheus), Anomaly Detection, Windows Sandbox Prototype.
- [ ] **Phase 5**: **(Current)** Windows Hardening (Low-IL), Advanced Threat Model, SIEM Integration.

---

### 🤝 Contributing & Feedback

If you find this project useful, please give it a ⭐️ **Star**! It helps the project grow.

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/XuebinMa/agent-guard/issues).
- **Security Audit**: See [docs/threat-model.md](docs/threat-model.md) for current security boundaries.
- **Vulnerabilities**: Please report security vulnerabilities privately.

---
**License**: MIT | Built with 🦀 for a safer AI future.
