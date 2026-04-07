# Phase 3 Design — agent-guard

> Status: **Final Design Document (PM Approved)**  
> Prerequisite: Phase 2 complete

## Overview
Phase 3 expands the guard's intelligence with context-aware policy rules, enables zero-downtime policy updates via atomic reloading, and extends the SDK to the Node.js ecosystem.

## M3.1: Context-aware Rules (DSL)

Enables rules that trigger based on the caller's identity or environment.

### Implementation
- **Engine**: Use the `evalexpr` crate for restricted expression evaluation.
- **Whitelist Variables**: `actor`, `agent_id`, `session_id`, `trust_level`, `tool`, `working_directory`.
- **Supported Operators**:
  - Comparison: `==`, `!=`
  - Logic: `&&`, `||`, `!`
- **Constraints (Strictly Enforced)**:
  - **No Functions**: `regex_match()`, `to_lower()`, etc. are strictly prohibited.
  - **No Arrays**: `val in ['a', 'b']` is not supported (use `||` logic).
  - **No Comparison Operators**: `>`, `<`, `>=`, `<=` are strictly disallowed.
  - **No Side-effects**: Assignment or mutable state is impossible.
- **Fail-fast**: Expressions are compiled and validated during policy load.

---

## M3.2: Atomic Policy Reloading

Enables updating security rules without restarting long-running agent processes.

### Implementation
- **Atomic Swap**: Use `ArcSwap` to replace the internal `PolicyEngine` instance.
- **Single-Request Isolation (Strict)**: 
    - Each `check()` or `execute()` request **MUST** capture a state snapshot (`ArcSwap::load()`) at the very beginning.
    - The entire request lifecycle (validation, decision, sandbox mode calculation, execution, and auditing) **MUST** use the **same** snapshot.
    - If a `reload()` occurs while a request is in-flight, the in-flight request is unaffected.
- **Methods (Core)**:
    - `Guard::reload_from_yaml(str)`
    - `Guard::reload_engine(PolicyEngine)`
- **Methods (SDK Convenience Layer)**:
    - `Guard::from_yaml_file(path)`
    - `Guard::reload_from_file(path)` - *Optional helper*
- **Audit & Versioning**:
    - Every `AuditEvent` includes `policy_version`.
    - `Guard::policy_version()` returns the current version string.

---

## M3.3: Node.js Support (napi-rs)

Expose the `agent-guard` SDK to the JavaScript/TypeScript ecosystem.

### Implementation
- **Async API**: Node.js bindings use `async` for execution.
- **Minimal API Surface**:
  - `check(tool, payload, context)`: Sync decision
  - `execute(tool, payload, context)`: Async execution outcome
  - `reload(yaml)`: Atomic policy update
  - `policy_version()`: Get version hash
- **TypeScript**: Auto-generated definitions included.

---

## M3.4: macOS Sandbox (Experimental)

Introduction of a best-effort sandbox for macOS using the native `sandbox-exec` (Seatbelt) facility.
