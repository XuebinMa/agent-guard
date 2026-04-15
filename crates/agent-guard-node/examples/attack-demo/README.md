# Attack Demo

This example is designed for demos, onboarding, and “before vs after” explanations.

It compares:

- an unsafe shell-like tool that would accept any command
- a guarded shell-like tool protected by `agent-guard`

## Run

From the repository root:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:attack --prefix crates/agent-guard-node
```

## What It Shows

- a safe command path
- an approval-required command path
- a clearly dangerous command being stopped before execution
- the difference between an unguarded handler and a guarded tool boundary

## Important Note

The “unsafe” side of the demo does **not** execute destructive host commands. It is a simulated baseline that shows what would have flowed into a real tool without a security boundary.

The guarded side is the real `agent-guard` path.
