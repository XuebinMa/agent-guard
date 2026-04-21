# Side-Effect Wedge Demo

This is the clearest short-term proof of what `agent-guard` is becoming:

**a runtime decision layer in front of real agent side effects**

The demo crosses three side-effect types in one flow:

- shell / terminal
- file write
- outbound mutation HTTP

It also shows the four runtime outcomes that matter in the short-term wedge:

- `execute`
- `deny`
- `ask_for_approval`
- `handoff`

---

## Run It

From the repository root:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:wedge --prefix crates/agent-guard-node
```

---

## What You Should See

The exact temp path and local port will vary, but the output shape should look like this:

```text
=== agent-guard side-effect wedge ===

[1] shell decision: execute
[1] shell output: summary:release-ready

[2] file decision: execute
[2] file path: /tmp/.../release-summary.txt
[2] file contents: summary:release-ready
[2] file status: executed

[3] http decision: execute
[3] http response: accepted:summary:release-ready

[4] remote publish decision: ask_for_approval
[4] remote publish status: ask_for_approval
[4] remote publish prompt: Confirmation required: rule 'prefix:https://api.example.com/' matched
```

---

## What This Proves

After this demo, you know five concrete things:

1. `agent-guard` is no longer only a shell story.
2. The runtime can now own execution for shell, file write, and outbound mutation HTTP.
3. One public decision surface can describe all of those side effects consistently.
4. Approval-required paths are still intercepted before the side effect becomes real.
5. The Node package is now a usable wedge for multi-step side-effect control, not just shell wrapping.

---

## What Stays Intentionally Narrow

This demo is still the short-term wedge, not a full platform claim.

It does not try to prove:

- generic execution control for every capability
- session-level planner intelligence
- enterprise approval workflow persistence
- broad browser or fetch orchestration

The point is narrower and stronger:

`agent-guard` now gives one execution decision boundary across a small, high-value set of real side effects.
