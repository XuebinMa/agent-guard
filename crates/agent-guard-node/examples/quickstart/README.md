# Node Quickstart

This is the shortest end-to-end `agent-guard` example for a new Node user.

## What It Shows

- how to load a `policy.yaml`
- how to wrap a shell-like tool with `wrapOpenAITool()`
- one allowed command
- one blocked command

## Run

From the repository root:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
node crates/agent-guard-node/examples/quickstart/app.js
```

Or, from `crates/agent-guard-node`:

```bash
npm run demo:quickstart
```

## Expected Output

- `echo hello from agent-guard` should succeed
- `git push origin main` should be blocked with `AgentGuardAskRequiredError`
