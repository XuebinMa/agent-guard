# Three-Minute Proof

This is the fastest way to answer one question:

**Will `agent-guard` actually stop risky AI tool calls before they execute?**

If you are evaluating the project for the first time, start here.

---

## What You Will See

This proof demo shows three paths:

- a safe shell command that is allowed
- a risky command that is stopped before execution
- a destructive command that is also stopped before execution

It also shows the contrast between:

- an unguarded handler that would accept the command
- a guarded handler wrapped by `agent-guard`

---

## Run It

From the repository root:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

---

## Expected Output Shape

You should see output similar to this:

```text
=== Safe Command ===
command: echo hello from attack demo
without guard: UNSAFE_HANDLER_WOULD_RUN:echo hello from attack demo
with guard: allowed

=== Approval Required Command ===
command: git push origin main
without guard: UNSAFE_HANDLER_WOULD_RUN:git push origin main
with guard: blocked

=== Destructive Command ===
command: rm -rf /
without guard: UNSAFE_HANDLER_WOULD_RUN:rm -rf /
with guard: blocked
```

The exact formatting may vary a little by platform or policy wording, but the important signal is:

- safe command: allowed
- risky command: blocked
- destructive command: blocked

---

## What This Proves

After this demo, you know four concrete things:

1. `agent-guard` is sitting on the tool boundary, not just in a prompt.
2. Allowed commands can still pass through and execute.
3. Risky commands can be stopped before the wrapped tool runs.
4. The project already has a usable Node integration path for shell-like tools.

---

## What It Does Not Prove Yet

This is an onboarding proof, not a production certification exercise.

It does not fully validate:

- your production policy design
- your host sandbox capabilities
- your framework-specific integration details
- your audit or receipt pipeline

For those, continue with:

- [Secure Shell Tools](secure-shell-tools.md)
- [Check vs Enforce](check-vs-enforce.md)
- [Framework Support Matrix](../../framework-support-matrix.md)

---

## Next Paths

Choose the next step that matches what you are trying to do:

- If you want the smallest real integration, go to [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md).
- If you want to explain the project to teammates, use [Attack Demo Playbook](attack-demo-playbook.md).
- If you want to protect a shell tool in your own app, continue with [Secure Shell Tools](secure-shell-tools.md).
