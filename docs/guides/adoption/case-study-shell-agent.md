# Case Study: Protecting a Shell-Enabled Agent

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Example Narrative |
| **Audience** | Evaluators, Platform Teams, Early Adopters |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Secure Shell Tools](../getting-started/secure-shell-tools.md), [Three-Minute Proof](../getting-started/three-minute-proof.md), [Check vs Enforce](../getting-started/check-vs-enforce.md) |

---

This example is intentionally simple. It is not meant to be a formal benchmark. It is meant to help a new user recognize their own problem quickly.

---

## Team Context

Imagine a team building an internal coding assistant that can use:

- `bash`
- file reads
- repository inspection commands

The assistant is useful because it can inspect code, run tests, and automate repetitive tasks.

The problem appears as soon as the tool boundary reaches a real shell.

---

## Before `agent-guard`

The team typically starts with:

- prompt instructions such as “never run destructive commands”
- some command filtering in application code
- tool wrapper logic written specifically for one framework

This is enough to get a prototype running, but the boundary is weak:

- the tool still depends heavily on model behavior
- risky commands can slip into application-level handlers
- there is little consistency across frameworks or teams
- auditability is limited to what the host app remembered to log

In short:

**the shell handler is still too close to the model.**

---

## After `agent-guard`

The team wraps the shell-like tool with `agent-guard`:

- `check` mode while they evaluate policy behavior
- `enforce` mode for the highest-risk paths

Now the flow changes:

1. the tool call is normalized
2. policy decides whether it is allowed, denied, or needs approval
3. execution can be routed through a sandbox path
4. the result becomes observable and auditable

This does not make the whole agent magically safe.

It does create a much better control point:

- the decision is explicit
- the integration is reusable
- the host boundary is no longer implicit

---

## What Improves Immediately

The team gets fast value in four areas:

### 1. Clearer Risk Boundary

The highest-risk path is no longer “whatever the model asked the shell to do.”

It becomes:

“whatever passed policy and execution controls.”

### 2. Better Adoption Path

The team can start with:

- one tool
- one framework adapter
- one proof demo

They do not need to redesign their entire runtime first.

### 3. Better Internal Trust

Security and platform reviewers can now reason about:

- where the control point exists
- what policy version was in effect
- which outcomes were allowed or blocked

### 4. Better Reuse

The control logic no longer lives entirely inside one app-specific wrapper.

That makes it easier to reuse across:

- code agents
- shell-enabled assistants
- internal tool gateways

---

## Best-Fit First Rollout

The best first rollout is usually:

1. protect a shell-like tool
2. start in `check` mode
3. validate policy behavior with the proof demo
4. move selected paths to `enforce`

This is much easier to adopt than trying to secure every tool category at once.

---

## Why This Case Study Matters

Most developers do not need a perfect security thesis on day one.

They need to answer:

- does this fit a real agent architecture?
- does it help with the dangerous part first?
- can I try it without rewriting everything?

For shell-enabled agents, the answer is now much closer to yes.

---

## Next Step

If this sounds like your use case, start with:

- [Three-Minute Proof](../getting-started/three-minute-proof.md)
- [Secure Shell Tools](../getting-started/secure-shell-tools.md)
- [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md)
