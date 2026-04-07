# Phase 3 Design — agent-guard

> Status: **Refined Design Document (Post-PM Review)**  
> Prerequisite: Phase 2 complete (Commit `320f025`)

## Overview

Phase 3 transitions `agent-guard` into a production-grade security middleware with fine-grained context awareness and hot-reloading capabilities.

### Refined Priorities (Post-PM Review)
1. **M3.1: Context-aware Policy** (High)
2. **M3.2: Atomic Policy Reloading** (High) - *Moved up*
3. **M3.3: Node.js Binding** (Medium)
4. **M3.4: macOS Experimental Sandbox** (Low) - *Reduced scope*

---

## M3.1: Context-aware Policy (Restricted DSL)

Enable rules that reference the caller's context. Per PM feedback, we will use a **restricted DSL** rather than a full scripting language to maintain auditability and performance.

### Implementation Strategy
- **Engine**: Use `evalexpr` for lightweight boolean expression evaluation.
- **Constraints (Hard)**:
    - **Context-Only**: Conditions evaluate only against `Context` fields. **No access to tool payload.**
    - **No functions**, loops, or side-effects.
    - **AOT Compilation**: Expressions are compiled and validated once at policy load time.
    - **Fail-fast**: Invalid expressions or unknown variables cause policy load failure.

### Supported Variable Whitelist
| Variable | Description |
|---|---|
| `actor` | Name of the user/process initiating the call. |
| `agent_id` | Identifier of the specific agent. |
| `session_id` | Unique ID for the current session. |
| `trust_level` | `untrusted`, `trusted`, or `admin`. |
| `tool` | Tool identifier (e.g., `bash`, `custom:my_tool`). |
| `working_directory` | Effective working directory. |

### Supported Operators
- Comparison: `==`, `!=`, `>`, `<`, `>=`, `<=`
- Logic: `&&`, `||`, `!`
- **Note**: Membership operator `in` and array literals are **NOT** supported in the initial release to keep the DSL minimal.

---

## M3.2: Atomic Policy Reloading

Enables updating security rules without restarting long-running agent processes.

### Implementation
- **Atomic Swap**: Use `ArcSwap` to replace the internal `PolicyEngine` instance.
- **Single-Request Isolation (Strict)**: 
    - Each `check()` or `execute()` request **MUST** capture a state snapshot (`ArcSwap::load()`) at the very beginning.
    - The entire request lifecycle (validation, decision, sandbox mode calculation, execution, and auditing) **MUST** use the **same** snapshot.
    - If a `reload()` occurs while a request is in-flight, the in-flight request is unaffected and continues with its initial snapshot.
- **Methods**:
    - `Guard::reload_from_yaml(str)`
    - `Guard::reload_engine(PolicyEngine)`
- **Audit & Versioning**:
    - Every `AuditEvent` includes `policy_version` (SHA-256 hash of the YAML).
    - `Guard::policy_version()` returns the current version.
- **Logging**: Reload success/failure events are logged to `stderr` with timestamps.

---

## M3.3: Node.js Binding (Minimal API)

Expand the ecosystem to JavaScript/TypeScript using `napi-rs`.

### Minimal API Surface
- `check(tool, payload, context)`: Returns a `Decision` object.
- `execute(input, sandbox)`: **Async** wrapper for command execution.
- `reload(yaml)`: Hot-reload the policy.
- TypeScript definitions included.

---

## M3.4: macOS Experimental Sandbox (Best-effort)

**Conservative Positioning**: This is an experimental adapter, not a guarantee of total isolation.

### Constraints
- **Feature Flag**: `macos-sandbox` (default off).
- **Tooling**: Uses `sandbox-exec` (Seatbelt).
- **Known Limitations**: Deprecated by Apple; requires SIP compatibility; no guarantees of future-proofing.
- **Audit**: Execution metadata will explicitly mark the sandbox backend used (`seccomp`, `sandbox-exec`, or `noop`).

---

## Roadmap (Updated)

| Milestone | Deliverable | Priority | Status |
|---|---|---|---|
| **M3.1** | Context-aware `if:` logic (evalexpr) | High | Pending |
| **M3.2** | `Guard::reload()` (ArcSwap) | High | Pending |
| **M3.3** | `agent-guard-node` package (napi-rs) | Medium | Pending |
| **M3.4** | `SeatbeltSandbox` (macos-sandbox flag) | Low | Pending |
