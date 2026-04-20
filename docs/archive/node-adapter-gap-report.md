# Node Adapter Readiness Audit: agent-guard

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Adapter Layer Delivered (v0.3.0 Audit) |
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
- **Consistency**: ✅ High-level adapters now surface typed JS errors (`AgentGuardDeniedError`, `AgentGuardAskRequiredError`, `AgentGuardExecutionError`) instead of exposing only raw N-API failure strings.

---

## 4. Payload Contract
- **Bare String Support**: ✅ Present. Shell strings are normalized to `{"command":"..."}` automatically.
- **Auto-wrapping**: ✅ Present in `Guard.check()` / `Guard.execute()` and exposed as `normalizePayload()`.
- **Validation**: 🟡 Relies primarily on Rust-side parsing after normalization.

---

## 5. Adapter Modes
- **Strategy**: ✅ High-level JS adapter layer is now shipped from `agent-guard-node`.
- **Check/Enforce**: ✅ `createGuardedExecutor()`, `wrapLangChainTool()`, and `wrapOpenAITool()` support `check`, `enforce`, and `auto`.
- **Error Model**: ✅ Decision-aware adapter errors carry `decision`, `policyVersion`, `sandboxType`, `receipt`, and `status`.

---

## 6. Demo / Runtime Truth
- **Demo Paths**:
  - `crates/agent-guard-node/demos/demo_langchain.js`
  - `crates/agent-guard-node/demos/demo_openai_handler.js`
  - `crates/agent-guard-node/demos/demo_check_vs_enforce.js`
- **API Realism**: ✅ Demos use the package-level adapter layer with real `@langchain/core` and `@openai/agents` packages instead of hand-rolled payload plumbing.
- **LCEL/Frameworks**: ✅ LangChain-style tool objects and OpenAI-style async handlers are both covered at the adapter layer and exercised against real framework runtimes.

---

## 📊 Audit Conclusion: 🟢 Green (Binding + Official Adapter Layer)

`agent-guard-node` now covers both the raw FFI contract and the first official Node-side adapter layer. The adapter entry points are also exercised against real `@langchain/core` and `@openai/agents` runtime objects, reducing the main Phase 1 adoption risk from wrapper semantics to longer-term ecosystem breadth.

### 🛠️ Required Fixes (Priority Order):
1. **Framework Depth**: Add SDK-specific registration helpers once the wrapper-level API settles.
2. **Compatibility Matrix**: Expand the real-framework validation into an explicit version support matrix in CI/docs.
3. **Extended Demos**: Expand beyond single-tool examples into multi-tool agent flows.
