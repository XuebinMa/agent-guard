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
| macOS | **Experimental**. Policy enforcement + experimental `SeatbeltSandbox` (Phase 3.4). |
| Windows | **Planned** (Phase 4). |

## Workspace Structure

```
agent-guard/
├── crates/
│   ├── agent-guard-core/       # Core types, policy engine, audit events
│   ├── agent-guard-validators/ # Bash and path validators
│   ├── agent-guard-sandbox/    # Sandbox trait + Seccomp (Linux) / Seatbelt (macOS)
│   ├── agent-guard-sdk/        # High-level Guard API (check + execute)
│   ├── agent-guard-python/     # PyO3 bindings
│   └── agent-guard-node/       # Node.js bindings (napi-rs)
├── demos/
│   ├── python/                 # LangChain and Python examples
│   └── node/                   # Node.js integration examples
├── docs/                       # Design and implementation documentation
├── policy.example.yaml
└── Cargo.toml                  # Workspace root
```

## Execute API (Phase 2 & 3)

`Guard::execute()` (Rust) and `guard.execute()` (Node/Python) provide a one-call solution that checks policy and then runs the command in a secure sandbox.

```rust
use agent_guard_sdk::{Guard, Tool, GuardInput, ExecuteOutcome};
use agent_guard_sandbox::SeccompSandbox; // Linux

let input = GuardInput::new(Tool::Bash, r#"{"command":"ls -la"}"#);
let sandbox = SeccompSandbox::new();

match guard.execute(&input, &sandbox) {
    Ok(ExecuteOutcome::Executed { output }) => {
        println!("stdout: {}", output.stdout);
    }
    _ => {}
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
