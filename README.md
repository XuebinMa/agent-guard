# 🛡️ agent-guard

> **End-to-end security barrier for AI agents.**  
> **Intercept tool calls, evaluate against policies, and execute in hardened sandboxes.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/Version-0.1.0--alpha-blue.svg)]()
[![Phase](https://img.shields.io/badge/Phase-4%20v1%20Complete-green.svg)]()

---

### 💡 Why agent-guard?

When Large Language Models (LLMs) are granted **Tool Use** or **Function Calling** capabilities, they effectively gain operating system privileges. **Prompt Injection** attacks can trick models into executing destructive commands like `rm -rf /` or performing unauthorized internal network scans.

`agent-guard` acts as an **independent security enforcement layer** between the LLM orchestrator and the host system:

- **Semantic Validation**: Intercept tool arguments and validate them against declarative policies using a restricted DSL.
- **Environment Isolation**: Mandatory process sandboxing using **Linux Seccomp-BPF** and **macOS Seatbelt**.
- **Audit & Compliance**: Structured, non-repudiable JSONL logs for every tool call and policy reload.
- **Anomaly Prevention**: Built-in rate limiting to prevent agents from entering accidental or malicious destructive loops.

---

### ✨ Key Features

- 🦀 **High Performance**: Built in Rust for sub-millisecond interception latency and memory safety.
- 📜 **Declarative Policy**: Simple YAML configuration supporting regex, path globbing, and context-aware variables.
- 🔄 **Atomic Hot-Reload**: Update policies on the fly with single-request snapshot isolation using `ArcSwap`.
- 🌍 **Multi-Language Ecosystem**:
  - **Node.js**: High-performance bindings via `napi-rs` with full TypeScript definitions.
  - **Python**: Deep integration with **LangChain 0.3** and native observability support.
- 🛡️ **Cross-Platform Sandboxing**:
  - **Linux**: Production-grade `Seccomp-BPF` syscall filtering.
  - **macOS**: Experimental `Seatbelt` filesystem and process isolation.
  - **Windows**: Early prototype using `Job Objects` for resource constraints.

---

### 🚀 Quick Start

#### Node.js / TypeScript
```typescript
import { Guard } from '@agent-guard/node';

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    deny: [{ prefix: "rm -rf" }]
`);

// Evaluate and execute in one call
const outcome = await guard.execute('bash', JSON.stringify({ command: 'ls -la' }));
if (outcome.outcome === 'executed') {
  console.log(outcome.output.stdout);
}
```

#### Python / LangChain
```python
import agent_guard
import json

# 1. Initialize security tracing (Phase 4)
agent_guard.init_tracing()

# 2. Use with your favorite framework
guard = agent_guard.Guard.from_yaml_file("policy.yaml")
decision = guard.check("bash", json.dumps({"command": "ls"}), actor="agent-007")

if decision.is_allow():
    # proceed with execution...
    pass
```

#### Rust SDK
```rust
use agent_guard_sdk::{Guard, Tool, GuardInput};

let guard = Guard::from_yaml_file("policy.yaml")?;
let input = GuardInput::new(Tool::Bash, r#"{"command":"cat /etc/passwd"}"#);

let decision = guard.check_sync(&input)?;
if decision.is_deny() {
    eprintln!("Security Blocked: {}", decision.message());
}
```

---

### 📊 Platform Support Matrix

| Security Feature | Linux (Seccomp) | macOS (Seatbelt) | Windows (Job Object) |
| :--- | :---: | :---: | :---: |
| **Policy Enforcement** | ✅ Full | ✅ Full | ✅ Full |
| **Syscall Filtering** | ✅ BPF | ❌ N/A | ❌ N/A |
| **Filesystem Isolation** | ✅ Strict | 🟡 Experimental | ❌ Planned |
| **Resource Limits** | ❌ Planned | ❌ N/A | 🟡 Experimental |
| **Anomaly Detection** | ✅ Full | ✅ Full | ✅ Full |

> **Security Note**: macOS and Windows implementations are currently **experimental prototypes**. While they provide valuable isolation, they do not yet match the syscall-level hardening provided by Seccomp on Linux.

#### Windows Specifics (Phase 4 Prototype)
- **Job Objects**: All tool calls on Windows are now wrapped in a dedicated Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- **Process Tree Cleanup**: If the parent process or the guard handle is closed, all child processes spawned by the agent are guaranteed to be terminated.
- **Fail-Closed**: Any failure in initializing the Job Object environment will result in a hard execution error rather than falling back to unmanaged execution.

---

### 🗺️ Roadmap

- [x] **Phase 1-2**: Core Engine, Linux Sandbox, Python Bindings.
- [x] **Phase 3**: Node.js Bindings, Atomic Reloading, Policy DSL.
- [x] **Phase 4**: **(Current)** Telemetry (Prometheus), Anomaly Detection, Threat Model v1.
- [ ] **Phase 5**: Windows Minifilter Driver, Distributed Audit Consistency, AI-driven Anomaly Analysis.

---

### 🤝 Contributing & Feedback

If you find this project useful, please give it a ⭐️ **Star**! It helps the project grow.

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/XuebinMa/agent-guard/issues).
- **Security Audit**: See [docs/threat-model.md](docs/threat-model.md) for current security boundaries.
- **Vulnerabilities**: Please report security vulnerabilities privately.

---
**License**: MIT | Built with 🦀 for a safer AI future.
