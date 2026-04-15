# Check vs Enforce

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational Guide |
| **Audience** | Developers, Integrators |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [User Manual](user-manual.md), [Secure Shell Tools](secure-shell-tools.md) |

---

`agent-guard` supports three high-level adapter modes:

- `check`
- `enforce`
- `auto`

The fastest way to choose correctly is:

- use `check` for API-like or local business-logic tools
- use `enforce` for shell-like tools that should run through the sandbox
- use `auto` when you want a lightweight preflight gate before running your original handler

This guide explains why.

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

`agent-guard` performs a preflight decision first.  
If the decision is `allow`, your original handler runs. Otherwise execution stops.

Flow:

`tool call -> guard.check() -> allow? -> original handler`

In practice, `auto` is a convenience mode for “guard first, then run the existing logic.”

---

## 2. Quick Decision Table

| Tool Type | Recommended Mode | Why |
| :--- | :--- | :--- |
| `bash`, `shell`, `terminal` | `enforce` | The execution boundary should move into `agent-guard`, not remain in your original handler. |
| local API wrapper | `check` | You usually want policy gating, then normal business logic. |
| search tool | `check` | These are typically non-OS actions and should keep their original handler. |
| calculator / utility tool | `check` | Sandboxing is less valuable than authorization and consistency. |
| migration path for an existing tool set | `auto` | Good for adding a first decision gate with low integration disruption. |

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
- terminal tool
- local command runner
- file-system-heavy tools that map cleanly into guarded execution

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

- you want a light migration step
- you need a quick policy gate before the original handler runs
- you are not ready to replace execution with sandboxed execution

This is useful when the team wants to answer:

- “Can we start blocking obviously risky requests today?”
- “Can we add approval/deny behavior without rewriting the tool implementation yet?”

`auto` is not the preferred final answer for shell execution when strong isolation is the goal. It is a convenient bridge.

---

## 6. Shell Tools: Default Recommendation

For true shell tools, the safest starting recommendation is:

- `mode: "enforce"`

This is important enough to repeat:

If the tool really executes shell commands, do not stop at `check` unless you have a strong reason. `check` still leaves the final OS execution path in your application handler.

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

1. Put all tools behind `check` or `auto`.
2. Observe which tool classes are the highest risk.
3. Move shell-like tools to `enforce`.
4. Keep lower-risk tools on `check`.

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
- `auto`: non-allow means your original handler does not run

---

## 10. One-Screen Recommendation

If you want the short version:

- protect `bash` first
- use `enforce` for shell tools
- use `check` for API and business tools
- use `auto` as a migration bridge, not the final architecture for high-risk shell execution
