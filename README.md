# agent-guard

> Policy-driven security enforcement SDK for AI agents — Rust workspace.

`agent-guard` is a composable Rust library that intercepts AI agent tool invocations, evaluates them against a declarative YAML policy, and produces structured `Allow / Deny / AskUser` decisions with a full audit trail.

---

## 🚀 Quick Start (Node.js & TypeScript)

If you're using Node.js, you can get started immediately with our high-performance bindings:

```bash
# Clone and enter the node crate
git clone https://github.com/XuebinMa/agent-guard
cd agent-guard/crates/agent-guard-node

# Build the native module
npm install
npm run build
```

**Usage:**

```typescript
import { Guard, TrustLevel } from '@agent-guard/node';

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
`);

// 1. Sync check
const decision = guard.check('bash', JSON.stringify({ command: 'ls -la' }));
console.log(decision.outcome); // "allow"

// 2. Async execute (Phase 2+)
const outcome = await guard.execute('bash', JSON.stringify({ command: 'ls -la' }));
if (outcome.outcome === 'executed') {
  console.log(outcome.output.stdout);
}
```

---

## 🚀 Quick Start (Rust)

```bash
git clone https://github.com/XuebinMa/agent-guard
cd agent-guard
cargo run -p agent-guard-sdk --example quickstart
```

---

## Platform Support

| Platform | Status |
|---|---|
| Linux | **Full Support**. Policy enforcement + OS-level sandbox (seccomp-bpf). |
| macOS | **Experimental Prototype**. Policy enforcement + best-effort filesystem isolation (`SeatbeltSandbox`). |
| Windows | **Experimental Prototype**. Policy enforcement + basic Job Object isolation. |

> **Note on macOS/Windows Sandbox**: The current implementations for macOS and Windows are experimental prototypes. They focus primarily on filesystem/process isolation and do not yet provide full network or global read restrictions. See [docs/sandbox-macos.md](docs/sandbox-macos.md) for details.

## Telemetry & Observability (Phase 4)

`agent-guard` now includes built-in support for structured logging and metrics:

- **Tracing**: Uses the `tracing` crate for high-granularity event logging.
- **Metrics**: Exposes Prometheus-compatible metrics (`policy_checks_total`, `execution_duration_seconds`) via the `prometheus-client` crate.
- **Anomaly Detection**: Basic frequency-based detection to prevent rapid-fire destructive tool calls.

## Workspace Structure

```
agent-guard/
├── crates/
│   ├── agent-guard-core/       # Core types, policy engine, audit events (M3.1, M3.2)
│   ├── agent-guard-validators/ # Bash and path validators
│   ├── agent-guard-sandbox/    # Sandbox trait + Seccomp (Linux) / Seatbelt (macOS)
│   ├── agent-guard-sdk/        # High-level Guard API (check + execute)
│   ├── agent-guard-python/     # PyO3 bindings (Phase 2)
│   └── agent-guard-node/       # Node.js bindings (napi-rs) (M3.3)
├── demos/
│   ├── python/                 # LangChain and Python examples
│   └── node/                   # Node.js integration examples
├── docs/                       # Design and implementation documentation
├── policy.example.yaml
└── Cargo.toml                  # Workspace root
```

## Execute API (Phase 3)

`Guard::execute_default()` (Rust) and `guard.execute()` (Node/Python) provide a one-call solution that automatically selects the best available sandbox for the current platform (Seccomp on Linux, Seatbelt on macOS).

**Rust Example:**

```rust
use agent_guard_sdk::{Guard, Tool, GuardInput, ExecuteOutcome};

let guard = Guard::from_yaml("version: 1")?;
let input = GuardInput::new(Tool::Bash, r#"{"command":"ls -la"}"#);

// Automatically chooses the best sandbox (Linux: Seccomp, macOS: Seatbelt)
match guard.execute_default(&input) {
    Ok(ExecuteOutcome::Executed { output }) => {
        println!("stdout: {}", output.stdout);
    }
    _ => {}
}
```

**Node.js Example:**

```typescript
import { Guard } from '@agent-guard/node';

const guard = Guard.fromYaml('version: 1');
const outcome = await guard.execute('bash', JSON.stringify({ command: 'ls' }));

if (outcome.outcome === 'executed') {
  console.log(outcome.output.stdout);
}
```

## Python Integration (Phase 2)

```python
import agent_guard
import json

guard = agent_guard.Guard.from_yaml_file("policy.yaml")
decision = guard.check("bash", json.dumps({"command": "ls"}), trust_level="trusted")
```

See `demos/` and `docs/` for full details.

## License

MIT
