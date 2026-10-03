# Check vs Enforce

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational Guide |
| **Audience** | Developers, Integrators |
| **Version** | 1.1 |
| **Last Reviewed** | 2026-10-02 |
| **Related Docs** | [User Manual](user-manual.md), [Secure Shell Tools](secure-shell-tools.md) |

---

`agent-guard` supports three high-level adapter modes:

- `check`
- `enforce`
- `auto`

The fastest way to choose correctly is:

- use `check` when you explicitly want a policy-only gate before existing host logic
- use `enforce` when the selected tool ID maps to a Guard-owned execution surface
- use `auto` for the runtime decision: exact `bash` is Guard-owned, non-shell
  tools go through `Guard.run()`, and the host runs only a returned `Handoff`

This guide explains how to choose based on where you want the execution boundary to live.

---

## 1. Mental Model

### `check`

`agent-guard` decides whether the tool call is allowed.  
If the decision is `allow`, your original handler still runs.

Flow:

`tool call -> guard.check() -> allow? -> original handler`

### `enforce`

`agent-guard` decides whether the tool call is allowed and then executes through the SDK sandbox path instead of your original handler.

Flow:

`tool call -> guard.execute() -> sandboxed execution`

### `auto`

`agent-guard` uses the unified runtime path. Exact tool ID `bash` goes through
Guard-owned execution. Non-shell tools call `guard.run()`; only a `Handoff`
invokes the original handler, after which the adapter submits a one-shot
terminal report. Guard-owned outcomes such as WriteFile or mutating HTTP can
execute without calling the handler.

Flow:

`tool call -> guard.run() -> deny / ask / Guard execute / host Handoff + report`

Shell-like custom IDs such as `shell`, `terminal`, `sh`, `zsh`, `cmd`, and
`powershell` fail closed in `auto` with `UnsupportedShellAlias`. Map a real
Bash-backed tool to exact `bash`, or deliberately choose an explicit mode.

---

## 2. Quick Decision Table

| Tool Type | Recommended Mode | Why |
| :--- | :--- | :--- |
| exact `bash` | `auto` or `enforce` | The execution boundary moves into the Guard-owned Bash path. |
| shell-like custom ID (`shell`, `terminal`, `sh`, …) | map to exact `bash` | `auto` rejects ambiguous shell aliases instead of silently handing commands back to the host. |
| local API wrapper | `check` | You usually want policy gating, then normal business logic. |
| search tool | `check` | These are typically non-OS actions and should keep their original handler. |
| calculator / utility tool | `check` | Sandboxing is less valuable than authorization and consistency. |
| mixed tool set using the runtime API | `auto` | Runtime decisions choose Guard execution or a correlated host handoff per call. |

---

## 3. When To Use `check`

Choose `check` when:

- the tool is not directly touching the OS shell
- you trust the underlying handler to do the real work
- you want the original handler output shape to stay unchanged
- you are integrating incrementally

Typical examples:

- web search
- internal RPC call
- database query wrapper
- application-specific business tools

Example:

```js
const guardedSearch = wrapOpenAITool(
  guard,
  async (input) => searchApi(input.query),
  {
    tool: 'web_search',
    mode: 'check',
  }
)
```

Use `check` when the main value you need is:

- authorization
- consistent policy
- logging and audit

not OS-level execution substitution.

---

## 4. When To Use `enforce`

Choose `enforce` when:

- the tool executes shell commands
- the tool should run under the SDK-selected sandbox
- the original handler should be bypassed
- the main risk is at the execution boundary itself

Typical examples:

- bash tool
- Guard-owned WriteFile or HTTP mutation paths
- another execution surface explicitly supported by `Guard.execute()`

Example:

```js
const guardedShell = wrapOpenAITool(
  guard,
  async () => {
    throw new Error('This should not execute in enforce mode')
  },
  {
    tool: 'bash',
    mode: 'enforce',
    resultMapper: (outcome) => outcome.output?.stdout ?? '',
  }
)
```

Use `enforce` when the main value you need is:

- stronger execution control
- sandbox selection
- tighter host protection

---

## 5. When To Use `auto`

Choose `auto` when:

- you want one runtime decision surface across mixed tools
- you need exact `bash` calls to stay Guard-owned
- you can close every returned host-handoff lifecycle with its terminal report

This is useful when the team wants to answer:

- “Should this call be denied, approved, Guard-executed, or handed to the host?”
- “Can every host action be correlated to the decision that authorized it?”

`auto` is not a name-based sandbox for arbitrary command runners. A
shell-like custom ID is a configuration error until it is mapped to the exact
owned ID `bash` or assigned an explicit mode.

---

## 6. Shell Tools: Default Recommendation

For true shell tools, the safest starting recommendation is:

- map the tool to exact `bash`
- use `mode: "auto"` or `mode: "enforce"`

This is important enough to repeat:

If the tool really executes shell commands, do not leave it under an alias and
do not stop at `check` unless you have a strong reason. `check` still leaves
the final OS execution path in your application handler.

For a step-by-step shell-specific guide, see [Secure Shell Tools](secure-shell-tools.md).

---

## 7. API Tools: Default Recommendation

For most API or business-logic tools, the safest practical starting recommendation is:

- `mode: "check"`

That keeps integration simple while still giving you:

- policy decisions
- blocked or ask-required behavior
- consistent context and auditability

---

## 8. Common Migration Pattern

This sequence works well for many teams:

1. Inventory which tool IDs can execute commands or mutate external state.
2. Map the real Bash-backed command runner to exact `bash`.
3. Put mixed non-shell tools behind `auto`, or explicitly choose `check` where
   the host intentionally owns execution.
4. Treat every returned Handoff ID as one-shot and report its terminal result.

This lets you increase protection without rewriting everything at once.

---

## 9. Error Behavior

Across the adapter layer, non-allow decisions become typed JS errors:

- `AgentGuardDeniedError`
- `AgentGuardAskRequiredError`
- `AgentGuardExecutionError`

Practical meaning:

- `check`: non-allow means your original handler does not run
- `enforce`: non-executed outcome becomes an adapter error
- `auto`: deny, ask, invalid verification, and shell-alias configuration errors
  stop the handler; a `Handoff` runs it once and must report completion

---

## 10. One-Screen Recommendation

If you want the short version:

- protect `bash` first
- map the real command runner to exact `bash`; do not rely on aliases
- use `auto` or `enforce` for that exact Bash tool
- use `check` for API and business tools
- use `auto` when you want the unified Guard-execute/Handoff lifecycle across a mixed tool set
