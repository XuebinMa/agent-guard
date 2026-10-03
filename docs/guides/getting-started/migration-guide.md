# 🚀 Migration Guide

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (current source) |
| **Audience** | Developers, DevOps |
| **Version** | 1.2 |
| **Last Reviewed** | 2026-10-02 |
| **Related Docs** | [User Manual](user-manual.md), [Capability Parity](../../concepts/capability-parity.md) |

---

This guide is for teams tightening a real deployment after the first proof or integration path is already working. It is not the best entry point for a first evaluation.

---

This guide helps you transition from basic `NoopSandbox` execution to the hardened, OS-level sandboxes provided by `agent-guard`.

---

## 1. 🛡️ Determine Host Capabilities

Before switching sandboxes, verify what your host operating system supports using the **Capability Doctor**.

```bash
cargo run -p guard-verify -- doctor --format text
```

---

## 2. 🏗️ The Three-Stage Adoption Path

### Phase 1: No-op (Development Only)
- **Benefit**: Zero setup, full speed.
- **Risk**: **NO OS-level protection.** If a tool is compromised, the host is vulnerable.

### Phase 2: Restricted Token / Seatbelt (Prototype/Internal)
- **Benefit**: Prevents most accidental filesystem writes outside the workspace.
- **Risk**: Network and advanced syscalls are still accessible on some platforms.

### Phase 3: Linux Host Sandboxing (Current Best Available Path)
- **Benefit**: Uses the strongest Linux backend available on the host today, with Seccomp-BPF filtering when built with the feature and Landlock write isolation where the host supports it.
- **Risk**: Path-aware isolation still depends on host capability and feature configuration; fallback hosts may still land on `NoopSandbox`.

---

## ⚠️ Security Boundaries (Transition Gaps)

| Transition | What you gain | What remains a gap |
| :--- | :--- | :--- |
| **No-op -> Low-IL** | Workspace write isolation on Windows. | Network access is still allowed by default. |
| **No-op -> Seatbelt**| Mandatory write-protection on macOS. | Global read access is still possible. |
| **No-op -> Linux Sandbox** | Seccomp filtering and/or Landlock-backed write isolation when the host and build support them. | Path-aware isolation is still host-dependent, and fallback hosts may still use `NoopSandbox`. |

---

## 3. ⚠️ Compatibility Notes: Low-IL (Windows)

1. **Writing to `%TEMP%`**: Low-IL processes cannot write to the user's standard temp directory.
2. **Accessing Registry**: Most registry write operations will be denied.
3. **Shell Redirection**: Ensure paths with spaces are correctly quoted for `cmd /C`.

---

## 4. 🛠️ Best Practices for Transition

1. **Start with `Read-Only`**: Even without a sandbox, `agent-guard`'s DSL will block unauthorized `write` tool calls.
2. **Audit First**: Run in `Phase 1` for a few days, review your `audit.jsonl`, and see which paths your agents actually need.
3. **Fail-Closed**: Always check the `ExecuteResult` for `SandboxError`.

---

## 5. Compatibility changes in the current source

These changes deliberately reject states that older releases accepted. Apply
them before upgrading a production integration:

| Area | Previous behavior | Current behavior | Migration |
| :--- | :--- | :--- | :--- |
| **Policy parsing** | Unknown fixed-schema keys, empty selectors and some malformed conditions could load and then fail to match. | Loading fails with a named schema/validation error. Runtime condition errors deny rather than becoming “not matched.” | Run the policy through `Guard::from_yaml` in CI. Correct misspellings, remove empty selector maps/strings, use valid HTTP method tokens, and fix condition operand types before rollout. `tools.custom` remains intentionally dynamic. |
| **Signed policy decisions** | Some decision-only entry points could return a normal verdict after detached-signature verification failed. | Every public check/decide/execute/run entry point returns `PolicyVerificationFailed`. | Treat that code as a hard configuration failure; do not retry through a different SDK method. |
| **Node adapter trust** | Omitting trust could select a broader implicit value. | Omitted trust is `Untrusted`, matching Rust and Python. | Pass `Trusted` explicitly only when a trusted host—not model output—makes that choice. |
| **HTTP handoff** | Some unrecognized or extension methods could be returned to the host as an unguarded handoff. | Only `GET`, `HEAD` and `OPTIONS` use the documented read-only handoff. Unsupported mutation/extension methods fail before network access. | Map custom methods to an explicitly implemented owned executor, or reject them in the host. Do not depend on implicit handoff. |
| **Decision deserialization** | Downstream Rust code could deserialize `DecisionReason`, or construct/destructure every field of approval variants. | `DecisionReason` no longer implements `Deserialize`; approval variants are `non_exhaustive` and validated constructors normalize blank prompts. | Deserialize stable audit/receipt wire records instead of runtime decision types. Construct approval decisions with `GuardDecision::ask_user` / `RuntimeDecision::ask_for_approval` and use accessor methods or wildcard patterns when matching. |
| **Plugin binary pairing** | A marketplace hook could invoke any `guard-hook` found on `PATH`. | The wrapper requires valid plugin metadata and an exact `guard-hook --version` match; faults fail open with a warning. | Install the matching binaries with the synchronized npm installer or the exact `cargo install ... --version` commands in the plugin guide. Monitor stderr for fail-open warnings. |

For shell execution, the five-minute default timeout and 4 MiB per-stream cap
may also surface `Timeout` or `OutputLimitExceeded` where an older call ran or
buffered indefinitely. Tighten the timeout if needed; do not remove the bounds.
