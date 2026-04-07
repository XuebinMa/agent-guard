# Phase 3 Design — agent-guard

> Status: **Refined Design Document (Post-PM Review)**  
> Prerequisite: Phase 2 complete (Commit `320f025`)

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
- **Constraints**:
  - **No Functions**: `regex_match()` or `to_lower()` are strictly prohibited.
  - **No Arrays**: `val in ['a', 'b']` is not supported (use `||` expansion).
  - **No Comparison Operators**: `>`, `<`, `>=`, `<=` are not allowed.
  - **No Side-effects**: Assignment or mutable state is impossible by design.
- **Fail-fast**: Expressions are compiled and validated during policy load. Invalid expressions prevent the engine from starting.

---

## M3.2: Atomic Policy Reloading

Enables updating security rules without restarting long-running agent processes.

### Implementation
- **Atomic Swap**: Use `ArcSwap` to replace the internal `PolicyEngine` instance.
- **Single-Request Isolation (Strict)**: 
    - Each `check()` or `execute()` request **MUST** capture a state snapshot (`ArcSwap::load()`) at the very beginning.
    - The entire request lifecycle (validation, decision, sandbox mode calculation, execution, and auditing) **MUST** use the **same** snapshot.
    - If a `reload()` occurs while a request is in-flight, the in-flight request is unaffected and continues with its initial snapshot.
- **Methods (Core)**:
    - `Guard::reload_from_yaml(str)`
    - `Guard::reload_engine(PolicyEngine)`
- **Methods (SDK Convenience Layer)**:
    - `Guard::from_yaml_file(path)`
    - `Guard::reload_from_file(path)` - *Optional helper*
- **Audit & Versioning**:
    - Every `AuditEvent` includes `policy_version` (SHA-256 hash of the YAML).
    - `Guard::policy_version()` returns the current version.
- **Structured Auditing**: 
    - Reload events are recorded as `PolicyReload` records in the audit log.
    - Includes `status` (success/failure), `old_version`, `new_version`, and `error` (if failed).

---

## M3.3: Node.js Support (napi-rs)

Expose the `agent-guard` SDK to the JavaScript/TypeScript ecosystem.

### Deliverables
- `agent-guard-node` crate using `napi-rs`.
- TypeScript definitions (`.d.ts`).
- Local `npm install` support for testing.

---

## M3.4: macOS Sandbox (Experimental)

Introduction of a best-effort sandbox for macOS using the native `sandbox-exec` (Seatbelt) facility.

### Constraints
- Lacks the fine-grained syscall filtering of Linux Seccomp.
- Focused on filesystem isolation (limiting `bash` to the workspace).
- Opt-in via feature flag: `macos-sandbox`.

---

## Roadmap

| Milestone | Deliverable | Priority | Status |
|---|---|---|---|
| **M3.1** | Context-aware `if:` logic (evalexpr) | High | **Completed** |
| **M3.2** | `Guard::reload()` (ArcSwap) | High | **Completed** |
| **M3.3** | `agent-guard-node` package (napi-rs) | Medium | Pending |
| **M3.4** | `SeatbeltSandbox` (macos-sandbox flag) | Low | Pending |
