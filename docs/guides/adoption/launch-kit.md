# Launch Kit

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Ready To Use |
| **Audience** | Maintainers, DevRel, Early Adopters |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Three-Minute Proof](../getting-started/three-minute-proof.md), [Attack Demo Playbook](../getting-started/attack-demo-playbook.md), [Framework Support Matrix](../../framework-support-matrix.md) |

---

This kit helps you explain `agent-guard` in a way that gets people to try it.

Use it when you are:

- posting a release or project update
- replying to “why would I use this?” questions
- recording a short demo clip
- giving a lightning talk or internal walkthrough

The guiding rule is simple:

**Lead with the risky tool call that gets stopped.**

Do not lead with architecture diagrams, parity tables, or future roadmap items.

---

## 1. One-Sentence Positioning

Use this sentence first:

> `agent-guard` puts a policy gate and OS sandbox in front of AI tool calls, so shell and other high-risk tools do not execute on prompt trust alone.

Shorter variant:

> `agent-guard` is a safety boundary for AI tool execution.

---

## 2. Who This Is For

The strongest-fit audience today is:

- engineers building code agents with shell access
- teams exposing tool-calling runtimes to LLMs
- platform or security teams that need auditable tool execution

If the audience has no tool execution, the message will feel less urgent.

---

## 3. The Best First Demo

Use the proof demo, not a deep architecture walkthrough.

Run:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

What to emphasize:

- safe command still works
- risky command does not silently run
- destructive command is stopped before execution

Reference:

- [Three-Minute Proof](../getting-started/three-minute-proof.md)

---

## 4. Thirty-Second Demo Script

Use this when recording a quick terminal clip:

1. “Here is a shell-like tool with no real boundary. It would accept whatever command the model sends.”
2. “Now here is the same path wrapped with `agent-guard`.”
3. “A normal command still works.”
4. “A risky command moves to an explicit decision instead of silently executing.”
5. “A destructive command gets stopped before it reaches the host.”

Close with:

> This is the difference between hoping the model behaves and enforcing a tool boundary.

---

## 5. Sixty-Second Video Outline

Use this for a slightly more polished clip:

### Opening Hook

“Most agent demos assume the tool call is safe if the prompt is safe. That is exactly the part we should not trust.”

### Demo Body

- run `npm run demo:proof --prefix crates/agent-guard-node`
- pause on the safe command result
- pause on the `git push` block
- pause on the destructive command block

### Close

“`agent-guard` sits between the model and the tool. It checks the call, can enforce execution boundaries, and gives you an auditable result instead of blind trust.”

---

## 6. Social Post Templates

### Post Template A: Product Value

```text
AI agents with shell tools should not rely on “please be safe” prompts.

We built `agent-guard` to put a policy gate and OS sandbox in front of tool calls.

The fastest proof:
- safe command: allowed
- git push: blocked / approval-required
- destructive command: stopped before execution

Try it:
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

### Post Template B: Builder Audience

```text
If you are building a code agent with `bash`, the dangerous part is not the prompt. It is the moment the tool call reaches the host.

`agent-guard` adds a decision boundary before execution:
- policy check
- sandbox selection
- auditable outcomes

Node quickstart and proof demo are live in the repo.
```

### Post Template C: Security Audience

```text
One practical way to improve agent security: move control from prompt text to the tool boundary.

`agent-guard` checks high-risk tool calls before execution and can enforce sandboxed execution paths, with receipts and audit hooks available for deeper trust workflows.
```

---

## 7. Comment Reply Templates

### “Why not just validate the command?”

Use:

> Command validation helps, but it still leaves the host relying on application logic alone. `agent-guard` is meant to add a reusable policy boundary and an execution boundary in front of the tool, so the control point is not just ad hoc app code.

### “Why not use prompts and allowlists?”

Use:

> Prompts and allowlists are useful, but they are not a durable enforcement boundary. This project is for teams that want the tool call itself to pass through policy and, where available, OS-level restrictions.

### “Who should care first?”

Use:

> Teams with shell-enabled or file-capable agents. That is where the risk is easiest to understand and the value is easiest to show quickly.

---

## 8. Asset Checklist

Before sharing publicly, make sure you have:

- one short terminal recording of `demo:proof`
- one static screenshot showing the blocked command output
- one link to [Three-Minute Proof](../getting-started/three-minute-proof.md)
- one link to [Framework Support Matrix](../../framework-support-matrix.md)
- one sentence that explains the problem before the feature list

---

## 9. What To Avoid

Avoid these common mistakes:

- leading with every platform detail at once
- claiming complete agent security
- starting with long architecture exposition
- burying the proof demo below roadmap content
- framing the project as a full agent framework

The project wins attention when the audience sees one dangerous tool path become a controlled one.

---

## 10. Recommended Sequence For Outreach

Use this order:

1. Share the proof demo clip or screenshot.
2. Link to [Three-Minute Proof](../getting-started/three-minute-proof.md).
3. Link to [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md) for people who want to try it.
4. Link to [Framework Support Matrix](../../framework-support-matrix.md) for people evaluating fit.

That sequence is much more effective than linking straight to architecture docs first.
