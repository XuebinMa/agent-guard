# Adapter Contract: agent-guard Integration Layer

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Baseline Established |
| **Audience** | FFI Binding maintainers (Python, Node.js, etc.) |
| **Version** | 1.2 |
| **Last Reviewed** | 2026-04-14 |

To ensure a consistent execution-control experience across bindings, all `agent-guard` language integrations MUST adhere to this contract.

---

## 1. Required FFI Surface (Guard Object)

The primary `Guard` object in any language MUST expose the following methods:

- `check(...) -> Decision`: Non-executing policy validation.
- `execute(...) -> ExecuteResult`: Policy validation followed by OS-level sandbox execution.
- `policy_version() -> str`: Return current policy hash.

### Parameters
Both `check` and `execute` MUST accept:
- `tool`: String identifier.
- `payload`: JSON-encoded string.
- `trust_level`, `agent_id`, `session_id`, `actor`: Context strings.

---

## 2. Payload Construction Contract

Adapters MUST normalize tool inputs into the following JSON schemas before calling the Rust SDK:

### A. Shell / Terminal Tools
Expected format: `{"command": "string"}`.
Adapters MUST wrap raw string inputs into this object for tools identified as shell providers.

### B. Generic / Structured Tools
Expected format: A JSON object representing the input arguments.
If the tool receives a single scalar value, it SHOULD be wrapped as `{"input": value}` to ensure a valid JSON object is passed to the Rust policy engine.

---

## 3. Adapter Support Scope (v0.3.0)

Adapters currently target three primary modes of operation:

### 🛡️ Enforcement Mode (`mode="enforce"`)
- **Primary Target**: Shell tools (`bash`, `shell`, `terminal`).
- **Mechanism**: The original tool execution logic is **replaced** by the `agent-guard` sandbox.
- **Outcome**: Returns the standard output of the sandbox.

### 🛡️ Authorization Mode (`mode="check"`)
- **Primary Target**: General API tools, local Python/JS functions.
- **Mechanism**: `guard.check()` is called as a gatekeeper. If allowed, the **original** tool logic executes.
- **Outcome**: Returns the original tool's output.

### 🛡️ Auto Mode (`mode="auto"`)
- **Primary Target**: High-level framework wrappers that want a simple preflight gate.
- **Mechanism**: `guard.check()` runs first. `allow` executes the original handler, while `deny` and `ask_user` block execution.
- **Outcome**: Returns the original handler output only when the preflight decision is `allow`.

---

## 4. Operational Requirements

1. **Fail-Closed**: Any internal error (binding failure, sandbox init failure) MUST block tool execution.
2. **Async Integrity**: Blocking FFI calls MUST be dispatched to background threads (e.g., `asyncio.to_thread`) to prevent stalling event loops.
3. **LCEL Compatibility**: For LangChain, high-level entry points like `invoke` MUST be patched to ensure the security wrapper is not bypassed.
