# Cross-language Parity Matrix

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Baseline Established (v0.2.0-rc1) |
| **Audience** | SDK consumers picking a language binding |
| **Last Reviewed** | 2026-04-30 |
| **Enforced by** | `tests/cross-language-parity/` + `parity-e2e` CI job |

---

## Why this exists

`agent-guard` ships three language surfaces:

- **Rust SDK** (`agent-guard-sdk`) — the source of truth.
- **Python binding** (`agent_guard`, PyO3 / abi3-py310).
- **Node binding** (`@agent-guard/node`, napi-rs).

Each surface evaluates the same policy and must produce the **same decision** for the **same inputs**. Drift between bindings is a security regression — a payload denied in one language must not be allowed in another. The `parity-e2e` CI job blocks merges whenever any of the 12 cross-language scenarios diverge.

This document is the human-readable map of what's covered. The machine truth lives in the `tests/cross-language-parity/` fixtures.

---

## API parity matrix

| Capability | Rust (`agent-guard-sdk`) | Python (`agent_guard`) | Node (`@agent-guard/node`) |
| :--- | :--- | :--- | :--- |
| Construct from inline YAML | `Guard::from_yaml(s)` | `Guard.from_yaml(s)` | `Guard.fromYaml(s)` |
| Construct from YAML file | `Guard::from_yaml_file(path)` | `Guard.from_yaml_file(path)` | `Guard.fromYamlFile(path)` |
| Signed policy load | `Guard::from_signed_yaml(...)` | `Guard.from_signed_yaml(...)` | `Guard.fromSignedYaml(...)` |
| Pure policy check | `guard.check(&input) → GuardDecision` | `guard.check(tool, payload, **ctx) → Decision` | `guard.check(tool, payload, ctx) → Decision` |
| Runtime decision mapping | `guard.decide(&input) → RuntimeDecision` | `guard.decide(tool, payload, **ctx) → RuntimeDecision` | `guard.decide(tool, payload, ctx) → RuntimeDecision` |
| Full sandbox execution | `guard.execute(&input, sandbox) → ExecuteOutcome` | `guard.execute(tool, payload, **ctx) → ExecuteResult` | `guard.execute(tool, payload, ctx) → ExecuteOutcome` |
| Runtime orchestration (Check → Filter → Audit → Sandbox/Handoff) | `guard.run(&input, sandbox) → RuntimeOutcome` | `guard.run(tool, payload, **ctx) → RuntimeOutcome` | `guard.run(tool, payload, ctx) → RuntimeOutcome` |
| Default sandbox factory | `Guard::default_sandbox()` | (built into `Guard.run` / `Guard.execute`) | (built into `guard.run` / `guard.execute`) |
| Host-handoff audit closure | `guard.report_handoff_result(rid, HandoffResult{...})` | `guard.report_handoff_result(rid, HandoffResult(...))` | `guard.reportHandoffResult(rid, {...})` |
| Atomic policy reload | `guard.reload_engine(engine)` / `guard.reload_from_yaml(s)` | `guard.reload_from_yaml(s)` | `guard.reloadFromYaml(s)` |
| Policy version | `guard.policy_version() → String` | `guard.policy_version()` | `guard.policyVersion()` |
| Policy hash (SHA-256) | `guard.policy_hash() → String` | `guard.policy_hash()` | `guard.policyHash()` |
| Policy verification status | `guard.policy_verification() → PolicyVerification` | `guard.policy_verification()` | `guard.policyVerification()` |

### Adapters (host-framework integration)

| Adapter | Python | Node |
| :--- | :--- | :--- |
| LangChain tool wrap | `wrap_langchain_tool(guard, tool, mode=..., ...)` | `wrapLangChainTool(guard, tool, options)` |
| OpenAI-style handler wrap | `wrap_openai_tool(guard, handler, tool=..., mode=..., ...)` | `wrapOpenAITool(guard, handler, options)` |

Adapter mode semantics are identical across both languages:

| Mode | Shell tool (`bash`/`shell`/`terminal`) | Non-shell tool |
| :--- | :--- | :--- |
| `enforce` | `Guard.execute()` (sandbox) | `Guard.execute()` |
| `check` | `Guard.check()` then host handler | `Guard.check()` then host handler |
| `auto` | `Guard.execute()` | `Guard.run()` (Handoff path closes audit via `report_handoff_result`) |

`check` and `auto` both **fail closed** on invalid policy signatures — see PR #20.

---

## Decision shapes

The three values that the `parity-e2e` job pins to byte-identity per scenario:

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `decision` | `"allow" \| "deny" \| "ask_user"` | `Guard.check` outcome label |
| `code` | `Option<String>` | Decision code (`PathOutsideWorkspace`, `DeniedByRule`, `AskRequired`, …); `None` for allow |
| `runtime_decision` | `"execute" \| "handoff" \| "deny" \| "ask_for_approval"` | `Guard.decide` outcome label |
| `runtime_code` | `Option<String>` | Same as `code` for `deny`/`ask_for_approval`; `None` otherwise |

Decision codes use the Rust `Debug` representation of `DecisionCode`. Python and Node bindings already format codes the same way internally, so strings match across languages.

---

## Configuration parity

| Concept | Rust enum | Python string | Node enum/string |
| :--- | :--- | :--- | :--- |
| `TrustLevel::Untrusted` | `Untrusted` (default) | `"untrusted"` | `"Untrusted"` |
| `TrustLevel::Trusted` | `Trusted` | `"trusted"` | `"Trusted"` |
| `TrustLevel::Admin` | `Admin` | `"admin"` | `"Admin"` |
| `Tool::Bash` | snake_case `"bash"` | `"bash"` | `"bash"` |
| `Tool::ReadFile` | `"read_file"` | `"read_file"` | `"read_file"` |
| `Tool::WriteFile` | `"write_file"` | `"write_file"` | `"write_file"` |
| `Tool::HttpRequest` | `"http_request"` | `"http_request"` | `"http_request"` |
| `PolicyMode::ReadOnly` | YAML: `read_only` | (set in policy YAML) | (set in policy YAML) |
| `PolicyMode::WorkspaceWrite` | YAML: `workspace_write` | (set in policy YAML) | (set in policy YAML) |
| `PolicyMode::FullAccess` | YAML: `full_access` | (set in policy YAML) | (set in policy YAML) |

Python accepts trust-level strings case-insensitively; Node accepts the `TrustLevel` enum values from `index.d.ts`. The Node parity runner normalizes `"trusted"` → `"Trusted"` for callers.

---

## Error mapping

| SDK condition | Rust | Python (adapter) | Node (adapter) |
| :--- | :--- | :--- | :--- |
| Policy deny | `GuardDecision::Deny { reason }` | `AgentGuardDeniedError` | `AgentGuardDeniedError` |
| Ask required | `GuardDecision::AskUser { message, reason }` | `AgentGuardAskRequiredError` | `AgentGuardAskRequiredError` |
| Sandbox/execution failure | `SandboxError` | `AgentGuardExecutionError` (with `cause=`) | `AgentGuardExecutionError` (with `cause`) |
| Invalid policy signature in `auto`/`check` | `RuntimeOutcome::Denied { reason: PolicyVerificationFailed }` | `AgentGuardDeniedError(code="PolicyVerificationFailed")` | `AgentGuardDeniedError(code="PolicyVerificationFailed")` |
| Handoff with host handler raise | (host responsibility) | propagate host exception **after** `report_handoff_result(exit_code=1)` | propagate host exception **after** `reportHandoffResult({exitCode: 1})` |

All exception classes carry the canonical attribute set: `policy_version`, `policy_verification_status`, `policy_verification_error`, `code`, `matched_rule`, `ask_prompt`. Python uses `_decision_to_error_attrs()` to populate them; Node uses `buildDecisionError()`.

---

## What the e2e suite covers

12 scenarios (see `tests/cross-language-parity/fixtures/scenarios.json`):

1. `bash_allow_echo` — bash allow path → Execute
2. `bash_destructive_rm` — `rm -rf /tmp/x` → deny / `PathOutsideWorkspace`
3. `bash_curl_pipe_bash` — regex deny rule → `DeniedByRule`
4. `bash_read_redirect_etc` — `cat < /etc/passwd` → deny / `PathOutsideWorkspace`
5. `bash_git_push_ask` — ask rule → `AskRequired` / AskForApproval
6. `write_workspace_allow` — write inside workspace → Execute
7. `write_etc_deny` — write `/etc/foo.conf` → deny
8. `read_workspace_handoff` — read inside workspace → Handoff
9. `read_shadow_deny` — read `/etc/shadow` → deny
10. `http_get_handoff` — GET → allow / Handoff
11. `http_post_execute` — POST → allow / Execute
12. `http_metadata_deny` — IMDS regex deny → `DeniedByRule`

If you add an SDK feature that affects decisions, add a scenario that exercises it.

---

## What is NOT in the parity matrix

These intentionally differ between languages or are scoped out of the e2e suite:

- **Sandbox execution outcomes** (real bash exec, real HTTP). Sandboxes are platform-specific; only the policy/decision layer is required to match.
- **Audit destinations**. SIEM webhook + JSONL file paths are configured in YAML; the writer behavior is the SDK's, not the binding's.
- **Naming conventions**. Python uses `snake_case` method names; Node uses `camelCase`. The data they return is identical.
- **Custom tool support**. Each binding exposes `Tool::Custom(name)` differently; the parity matrix only covers builtin tool names today.

---

## Adding a binding or feature

When adding a new binding (e.g. Go, Ruby), the acceptance bar is:

1. Implement `Guard.from_yaml`, `check`, `decide` (minimum runtime API).
2. Add a runner under `tests/cross-language-parity/runners/runner.<lang>`.
3. Wire it into `compare.py` so all four runners are diffed.
4. Add the `parity-<lang>-e2e` step to `.github/workflows/ci.yml` (mandatory, not `continue-on-error`).
5. Update this matrix with the new column.

When adding a new SDK feature (new decision code, new RuntimeDecision shape, new tool):

1. Add the feature in `agent-guard-core` / `agent-guard-sdk`.
2. Expose it through Python (`crates/agent-guard-python/src/`) and Node (`crates/agent-guard-node/src/`).
3. Add at least one fixture scenario in `tests/cross-language-parity/fixtures/scenarios.json` that exercises it.
4. The `parity-e2e` job will fail until all three runners agree.
