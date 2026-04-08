# Node Adapter Readiness Audit: agent-guard

| Field | Details |
| :--- | :--- |
| **Status** | 🟠 Needs Fixes (v0.3.0 Audit) |
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

---

## 2. Result Schema
| Field | Status | Notes |
| :--- | :--- | :--- |
| `status` | ❌ Missing | Current `ExecuteOutcome` uses `outcome` instead of `status`. |
| `decision` | ✅ Partial | Present in `ExecuteOutcome`, but `Decision` object lacks `policy_version`. |
| `output` | ✅ Exported | `exit_code`, `stdout`, `stderr` are present. |
| `policy_version` | ❌ Missing | Not returned inside `ExecuteOutcome` or `Decision`. |
| `sandbox_type` | ❌ Missing | Not exposed in any result structure. |
| `receipt` | ❌ Missing | Ed25519 receipts not yet integrated into Node FFI. |

---

## 3. Async Semantics
- **Promise Support**: ✅ `execute()` returns a native JS Promise.
- **Non-blocking**: ✅ Uses N-API `async worker` pattern.
- **Consistency**: 🟡 Errors use `napi::Error` (Status: GenericFailure), which is standard but could be more granular.

---

## 4. Payload Contract
- **Bare String Support**: ❌ Risk. The FFI expects a JSON string, but there is no helper to normalize inputs.
- **Auto-wrapping**: ❌ Missing. Unlike the Python adapter, users must manually call `JSON.stringify({"command": "..."})`.
- **Validation**: 🟡 Relies entirely on Rust-side parsing.

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

## 📊 Audit Conclusion: 🟠 Yellow (Workable with Fixes)

`agent-guard-node` is fundamentally sound in its FFI implementation but suffers from the same **Contract Drift** as the initial Python version. It is currently a "Raw Binding" rather than an "Adapter".

### 🛠️ Required Fixes (Priority Order):
1. **Schema Alignment**: Rename `outcome` to `status` in `ExecuteOutcome` and add `policy_version` to all results.
2. **Expose Sandbox Info**: Add `sandbox_type` to `ExecuteOutcome`.
3. **Payload Normalization**: Implement a JS-side `wrapTool()` helper similar to the Python version to handle `{"command": "..."}` wrapping automatically.
4. **Receipt Support**: Add `receipt` field to results and expose verification logic.
