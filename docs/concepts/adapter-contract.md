# Adapter Contract: agent-guard Integration Layer

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Baseline Established |
| **Audience** | FFI Binding maintainers (Python, Node.js, etc.) |
| **Version** | 1.3 |
| **Last Reviewed** | 2026-10-02 |

To ensure a consistent execution-control experience across bindings, all `agent-guard` language integrations MUST adhere to this contract.

---

## 1. Required FFI Surface (Guard Object)

The primary `Guard` object in any language MUST expose the following methods:

- `check(...) -> Decision`: Non-executing policy validation.
- `execute(...) -> ExecuteResult`: Policy validation followed by OS-level sandbox execution.
- `run(...) -> RuntimeOutcome`: Unified runtime decision, sandbox, or host-handoff path.
- a fallible handoff-report method: Close a one-shot host-handoff lifecycle;
  reject unknown, expired, or duplicate request IDs.
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
- **Primary Target**: Tools for which the caller explicitly wants
  Guard-owned execution. The only built-in shell executor is the exact tool ID
  `bash`; names such as `shell` and `terminal` remain custom tool IDs.
- **Mechanism**: The original tool execution logic is **replaced** by the
  `agent-guard` execution path. Unsupported custom execution surfaces fail
  closed; they are not silently treated as `bash` aliases.
- **Outcome**: Returns the standard output of the sandbox.

### 🛡️ Authorization Mode (`mode="check"`)
- **Primary Target**: General API tools, local Python/JS functions.
- **Mechanism**: `guard.check()` is called as a gatekeeper. If allowed, the **original** tool logic executes.
- **Outcome**: Returns the original tool's output.

### 🛡️ Auto Mode (`mode="auto"`)
- **Primary Target**: High-level framework wrappers that want one safe default across shell and non-shell tools.
- **Mechanism**: The exact built-in tool ID `bash` uses `guard.execute()`.
  Non-shell tool IDs use
  `guard.run()`; a `Handoff` invokes the original handler and then submits one
  terminal report using the returned request ID. Older bindings without the
  runtime API may fall back to `check`, but current Python and Node bindings do
  not. Recognized shell-like custom IDs fail closed with
  `UnsupportedShellAlias`; the host must map a real Bash-backed tool to exact
  `bash` or choose an explicit mode.
- **Outcome**: A completed host action is returned only after its handoff report
  succeeds. If the handler fails, preserve that original error; if reporting
  also fails, attach the reporting error instead of hiding either failure. If
  only the report fails after the action completed, the execution error must
  carry the result, handoff request ID, attempted terminal report, original
  policy verification metadata, and an explicit completed/do-not-retry marker
  so an operator can reconcile the lifecycle without rerunning the action.

---

## 4. Operational Requirements

1. **Fail-Closed**: Any internal error (binding failure, sandbox init failure) MUST block tool execution.
2. **Async Integrity**: Blocking FFI calls MUST be dispatched to background threads (e.g., `asyncio.to_thread`) to prevent stalling event loops.
3. **LCEL Compatibility**: For LangChain, high-level entry points like `invoke` MUST be patched to ensure the security wrapper is not bypassed.
4. **Snapshot Integrity**: A returned decision and its policy version and
   verification metadata MUST come from the same immutable policy snapshot.
