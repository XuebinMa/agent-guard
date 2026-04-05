# Phase 2 Design — agent-guard

> Status: pre-implementation design document  
> Prerequisite: Phase 1 complete (commit `71b8604`, 169 tests passing)

## Overview

Phase 2 has three parallel workstreams. They are independent and can be developed concurrently, but the Python binding (P1) is highest priority because it unlocks ecosystem integration.

| Workstream | Priority | Milestone |
|---|---|---|
| Python binding (pyo3) | P1 | Usable `check()` from Python |
| LangChain / generic Python demo | P1 | Two demo scripts showing real agent integration |
| Linux seccomp sandbox | P2 | `execute()` with kernel-level enforcement |

---

## Workstream 1: Python Binding (pyo3)

### Design constraints

- Wrap only `Guard::check_tool()` in Phase 2. `execute()`, sandbox, and config management are Phase 3.
- The Rust crate stays unchanged. The binding is a thin translation layer with no business logic.
- Errors are converted to Python exceptions; panic is caught at the boundary.
- The returned decision is a Python dataclass (not a raw dict), to give IDE autocomplete and type checking.

### Crate layout

```
crates/
  agent-guard-python/     ← new crate, type = cdylib
    Cargo.toml
    src/
      lib.rs              ← PyModule registration
      types.rs            ← PyGuard, PyDecision, PyDecisionReason
      error.rs            ← GuardError (Python exception)
```

`Cargo.toml` additions:
```toml
[lib]
name = "agent_guard"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.21", features = ["extension-module"] }
agent-guard-sdk = { path = "../agent-guard-sdk" }
```

### Python API surface (minimal, frozen for Phase 2)

```python
import agent_guard

# Construction
guard = agent_guard.Guard.from_yaml(yaml_str: str) -> Guard
guard = agent_guard.Guard.from_yaml_file(path: str) -> Guard

# Evaluation
decision = guard.check(
    tool: str,           # "bash" | "read_file" | "write_file" | "http_request" | custom id
    payload: str,        # raw JSON string (same contract as Rust)
    trust_level: str,    # "untrusted" | "trusted" | "admin"
    # optional context fields:
    agent_id: str | None = None,
    session_id: str | None = None,
    actor: str | None = None,
    working_directory: str | None = None,
) -> Decision

# Decision is a dataclass:
@dataclass
class Decision:
    outcome: str          # "allow" | "deny" | "ask_user"
    message: str | None   # populated for deny/ask_user
    code: str | None      # e.g. "DENIED_BY_RULE", "DESTRUCTIVE_COMMAND"
    matched_rule: str | None
    ask_prompt: str | None  # populated only for ask_user

# Convenience predicates
decision.is_allow() -> bool
decision.is_deny() -> bool
decision.is_ask() -> bool
```

### Error handling

All Rust errors surface as `agent_guard.GuardError(Exception)`:

```python
try:
    guard = agent_guard.Guard.from_yaml("invalid yaml")
except agent_guard.GuardError as e:
    print(e)  # "policy error: ..."
```

Panics inside Rust are caught by pyo3's `catch_unwind` and converted to `RuntimeError`.

### Build and packaging

```toml
# pyproject.toml (workspace root)
[build-system]
requires = ["maturin>=1.4"]
build-backend = "maturin"

[tool.maturin]
features = ["pyo3/extension-module"]
manifest-path = "crates/agent-guard-python/Cargo.toml"
```

Development workflow:
```bash
pip install maturin
maturin develop --manifest-path crates/agent-guard-python/Cargo.toml
python -c "import agent_guard; print(agent_guard.__version__)"
```

### Test plan

- Unit tests in `crates/agent-guard-python/tests/test_guard.py` using pytest
- Mirror the Rust integration test scenarios: allow/deny/ask_user, JSON payload, invalid YAML
- CI: `maturin build --release` + `pytest`

---

## Workstream 2: Python Integration Demos

Two demos, independent of each other. Both live in `demos/python/`.

### Demo A: LangChain tool-use guard

Shows how to wrap a LangChain `Tool` with agent-guard so every invocation is checked before execution.

```python
# demos/python/langchain_demo.py
from langchain.tools import BaseTool
import agent_guard
import subprocess

guard = agent_guard.Guard.from_yaml_file("policy.example.yaml")

class GuardedBashTool(BaseTool):
    name = "bash"
    description = "Run a shell command (policy-enforced)"

    def _run(self, command: str) -> str:
        d = guard.check("bash", command, trust_level="trusted")
        if d.is_deny():
            return f"[DENIED] {d.message}"
        if d.is_ask():
            return f"[ASK_USER] {d.ask_prompt}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout or result.stderr

# Plugs into any LangChain agent unchanged.
```

Key points to show in the demo:
- Guard is constructed once at startup, not per-call (policy is loaded once)
- The tool interface is unchanged from LangChain's perspective
- Deny/AskUser are surfaced as string responses, letting the LLM handle them gracefully

### Demo B: Generic Python wrapper (framework-agnostic)

For users not on LangChain. Shows the pattern for wrapping any agent framework.

```python
# demos/python/generic_demo.py
import agent_guard
import json

guard = agent_guard.Guard.from_yaml("""
version: 1
default_mode: workspace_write
tools:
  bash:
    deny:
      - prefix: "rm -rf"
  read_file:
    deny_paths:
      - "/etc/**"
      - "**/.ssh/**"
audit:
  enabled: true
  output: stdout
""")

def agent_tool_call(tool_name: str, args: dict, trust_level: str = "trusted") -> dict:
    """
    Generic interceptor: call before executing any agent tool.
    Returns {"allowed": True} or {"allowed": False, "reason": "..."} or {"ask": True, "prompt": "..."}.
    """
    payload = json.dumps(args)
    d = guard.check(tool_name, payload, trust_level=trust_level)
    if d.is_allow():
        return {"allowed": True}
    if d.is_deny():
        return {"allowed": False, "reason": d.message, "code": d.code}
    return {"ask": True, "prompt": d.ask_prompt}

# Usage with any agent framework:
result = agent_tool_call("bash", {"command": "ls -la"})
result = agent_tool_call("read_file", {"path": "/etc/passwd"})
result = agent_tool_call("read_file", {"path": "/workspace/main.py"})
```

---

## Workstream 3: Linux Seccomp Sandbox

### Design

`agent-guard-sandbox` already has `NoopSandbox`. Phase 2 adds `SeccompSandbox` for Linux.

The `Sandbox` trait (already defined) specifies:

```rust
pub trait Sandbox: Send + Sync {
    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult;
}
```

`SeccompSandbox` wraps the command in a subprocess with a seccomp-bpf filter that allows only the syscalls required for the approved operation, based on the `PermissionMode`.

### Syscall allowlists by mode

| Mode | Allowed syscalls (illustrative) |
|---|---|
| `ReadOnly` | `read`, `open`/`openat` (O_RDONLY), `stat`, `lstat`, `fstat`, `close`, `mmap` (PROT_READ), `exit_group` |
| `WorkspaceWrite` | ReadOnly + `write`, `open` (O_WRONLY/O_RDWR within workspace), `creat`, `unlink`, `rename`, `mkdir` |
| `FullAccess` | All syscalls permitted (no seccomp filter applied) |

The workspace constraint is enforced at the path level by the existing validator; seccomp provides defense-in-depth by blocking syscalls that should never appear regardless of path.

### Crate changes

```
crates/agent-guard-sandbox/
  Cargo.toml         ← add seccomp = ["libseccomp"] feature flag
  src/
    lib.rs
    noop.rs          ← existing
    linux.rs         ← new: SeccompSandbox (cfg(target_os = "linux"))
```

`Cargo.toml`:
```toml
[features]
seccomp = ["dep:libseccomp"]

[dependencies]
libseccomp = { version = "0.3", optional = true }
```

Usage:
```bash
cargo build --features agent-guard-sandbox/seccomp
```

### `SandboxContext` and `SandboxResult`

```rust
pub struct SandboxContext {
    pub mode: PolicyMode,
    pub working_directory: PathBuf,
    pub timeout_ms: Option<u64>,
}

pub enum SandboxResult {
    Ok { stdout: String, stderr: String, exit_code: i32 },
    Denied { reason: String },
    Timeout,
    Error(String),
}
```

### Integration with Guard

Phase 2 adds `Guard::execute()` alongside the existing `Guard::check()`:

```rust
// check() — decision only, no execution (Phase 1, stable)
pub fn check(&self, input: &GuardInput) -> GuardDecision;

// execute() — check + run in sandbox (Phase 2, Linux only)
#[cfg(feature = "sandbox")]
pub fn execute(&self, input: &GuardInput) -> ExecuteResult;
```

`execute()` calls `check()` first; if `Allow`, it passes the command to the sandbox. `Deny` and `AskUser` are returned immediately without execution.

### Test plan

- Unit tests: verify syscall filter construction, workspace path enforcement
- Integration tests: run real commands under `SeccompSandbox`, assert allowed/blocked behavior
- CI: `cfg(target_os = "linux")` gate, only runs on Linux runners

---

## Milestone Summary

| Milestone | Deliverable | Definition of Done |
|---|---|---|
| **M2.1** Python binding alpha | `crates/agent-guard-python`, `maturin develop` works | `pytest` passes, `check()` callable from Python |
| **M2.2** Python demos | `demos/python/langchain_demo.py` + `generic_demo.py` | Both scripts run end-to-end with policy file |
| **M2.3** Seccomp sandbox | `crates/agent-guard-sandbox/src/linux.rs` | `cargo test --features seccomp` passes on Linux |
| **M2.4** `execute()` integration | `Guard::execute()` in SDK | Integration test: allow → executes, deny → short-circuits |

## Open questions for Phase 2 kickoff

1. **pyo3 version**: Use 0.21 (latest stable) or 0.22 (if released)?  
2. **LangChain version**: 0.1.x (stable) or 0.2.x (breaking changes in tool API)?  
3. **Seccomp library**: `libseccomp` crate or raw `syscall` via `libc`? The crate is easier but adds a C dependency.  
4. **`execute()` timeout**: Should it be a policy YAML field or a `GuardInput` field?  
5. **Windows Phase 2 or Phase 4**: Current plan is Phase 4. Confirm no change.

## Architecture constraints (carry forward from Phase 1)

- `effective_mode()` is the single source of truth for mode resolution — never derive from `trust_level` alone.
- `payload` remains a raw JSON string at the SDK boundary; structured extraction happens inside the engine.
- `check()` never executes code; `execute()` is always a separate call.
- Python binding has zero business logic — all policy evaluation stays in Rust.
