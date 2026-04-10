# Node Adapter Readiness Audit: agent-guard

| Field | Details |
| :--- | :--- |
| **Status** | 🟡 Mostly Aligned (v0.3.0 Audit) |
| **Target** | `agent-guard-node` |
| **Auditor** | Code Analyst |
| **Contract Version** | 1.1 |

---

## 1. Export Surface
| Method | Status | Notes |
| :--- | :--- | :--- |
| `check()` | ✅ Exported | Sync FFI call. |
| `execute()` | ✅ Exported | Async FFI call (N-API async). |
| `reload()` | ✅ Exported | Atomic reload supported. |
| `policy_version()`| ✅ Exported | Returns current hash. |
| `setSigningKey()` | ✅ Exported | Receipt signing key can be configured from JS. |

---

## 2. Result Schema
| Field | Status | Notes |
| :--- | :--- | :--- |
| `status` | ✅ Present | `ExecuteOutcome` uses `status` (`executed`, `denied`, `ask_required`). |
| `decision` | ✅ Present | Nested decisions include `policy_version`. |
| `output` | ✅ Exported | `exit_code`, `stdout`, `stderr` are present. |
| `policy_version` | ✅ Present | Returned in both `ExecuteOutcome` and `Decision`. |
| `sandbox_type` | ✅ Present | Exposed on execution results. |
| `receipt` | ✅ Present | JSON-encoded signed receipt when signing is enabled. |

---

## 3. Async Semantics
- **Promise Support**: ✅ `execute()` returns a native JS Promise.
- **Non-blocking**: ✅ Uses N-API `async worker` pattern.
- **Consistency**: 🟡 Errors use `napi::Error` (Status: GenericFailure), which is standard but could be more granular.

---

## 4. Payload Contract
- **Bare String Support**: ✅ Present. Shell strings are normalized to `{"command":"..."}` automatically.
- **Auto-wrapping**: ✅ Present in `Guard.check()` / `Guard.execute()` and exposed as `normalizePayload()`.
- **Validation**: 🟡 Relies primarily on Rust-side parsing after normalization.

---

## 5. Adapter Modes
- **Strategy**: ❌ No high-level adapter. The package only provides raw FFI bindings.
- **Check/Enforce**: ❌ No JS-level wrapper to switch between "Authorization-only" and "Enforced" modes.

---

## 6. Demo / Runtime Truth
- **Demo Path**: `demos/node/basic_usage.js`.
- **API Realism**: 🟡 Calls real FFI, but manually constructs payloads.
- **LCEL/Frameworks**: ❌ No LangChain JS or OpenAI JS adapter.

---

## 📊 Audit Conclusion: 🟡 Yellow (Raw Binding, Contract Mostly Aligned)

`agent-guard-node` is fundamentally sound in its FFI implementation and now aligns with the current result schema and payload contract. It is still primarily a "Raw Binding" rather than a high-level framework adapter.

### 🛠️ Required Fixes (Priority Order):
1. **High-level JS Adapter**: Add a first-class LangChain/OpenAI JS wrapper for `check` vs `enforce` flows.
2. **Error Granularity**: Consider richer JS error classes instead of generic N-API failures.
3. **Runtime Demos**: Expand JS examples beyond the low-level FFI smoke test.
