# Adapter Contract: agent-guard Integration Layer

> Status: **Draft**  
> Version: **1.0**  
> Target: FFI Binding maintainers (Python, Node.js, etc.)

To ensure a consistent security experience across ecosystems, all `agent-guard` language bindings MUST adhere to this contract.

---

## 1. Required FFI Surface (Guard Object)

The primary `Guard` object in any language MUST expose the following methods:

- `check(...) -> Decision`: Non-executing policy validation.
- `execute(...) -> ExecuteResult`: Policy validation followed by OS-level sandbox execution.
- `reload_from_yaml(yaml: str)`: Atomic policy update.
- `policy_version() -> str`: Return current policy hash.

### Parameters
Both `check` and `execute` MUST accept:
- `tool`: String identifier.
- `payload`: JSON-encoded string.
- `trust_level`: "untrusted" (default), "trusted", "admin".
- `agent_id`, `session_id`, `actor`: Optional correlation strings.

---

## 2. Unified Result Semantics

### Decision Object (Check)
- `outcome`: "allow", "deny", "ask_user".
- `code`: The `DecisionCode` string (e.g., `DENIED_BY_RULE`).
- `policy_version`: The hash of the policy used for this specific check.

### ExecuteResult Object (Execute)
- `status`: "executed", "denied", "ask_required".
- `output`: Optional object containing `stdout`, `stderr`, `exit_code`.
- `decision`: Required if status is NOT "executed".
- `policy_version`: Must reflect the snapshot used during execution.

---

## 3. Adapter Design Patterns (Wrappers)

When building framework-specific adapters (e.g., for LangChain), use the following patterns:

### A. Authorization Mode (`mode="check"`)
- **Workflow**: `guard.check()` -> if Allow -> `original_logic()`
- **Usage**: For general API tools or local Python functions where sandbox execution is not possible/desired.

### B. Enforcement Mode (`mode="enforce"`)
- **Workflow**: `guard.execute()` -> return sandbox output directly.
- **Usage**: For shell, terminal, or system-level tools where OS isolation is required.

---

## 4. Operational Requirements

1. **Fail-Closed**: Any internal error (binding failure, sandbox init failure) MUST result in an exception that blocks tool execution.
2. **Async Integrity**: 
   - Async methods (e.g., `_arun`) MUST be supported. 
   - Blocking FFI calls MUST be dispatched to background threads (e.g., `asyncio.to_thread` in Python) to avoid stalling the event loop.
3. **Traceability**: The adapter MUST ensure that `agent_id` and `actor` are passed through from the framework context to the SDK for auditing.
