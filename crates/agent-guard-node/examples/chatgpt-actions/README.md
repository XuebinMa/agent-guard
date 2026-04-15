# ChatGPT Actions Example

This example demonstrates the practical architecture for using `agent-guard` with a ChatGPT Custom GPT Action:

`Custom GPT` -> `Action` -> `HTTP API` -> `agent-guard` -> `shell tool`

## Files

- `policy.yaml`: guard policy used by the example server
- `server.js`: minimal HTTP server
- `openapi.yaml`: Action schema to import into the GPT editor

## Run

From the repository root:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:chatgpt-actions --prefix crates/agent-guard-node
```

The server listens on `http://127.0.0.1:8787`.

## Local Test

Health check:

```bash
curl http://127.0.0.1:8787/health
```

Allowed command:

```bash
curl -s http://127.0.0.1:8787/run-shell \
  -H 'content-type: application/json' \
  -d '{"command":"echo hello from chatgpt action"}'
```

Blocked command:

```bash
curl -s http://127.0.0.1:8787/run-shell \
  -H 'content-type: application/json' \
  -d '{"command":"git push origin main"}'
```

## Using It In ChatGPT

1. Make the server reachable over HTTPS.
2. Open `https://chatgpt.com/gpts/editor`.
3. Create a GPT and add a new Action.
4. Paste or import `openapi.yaml`.
5. Update the `servers` URL in the schema to your reachable host.
6. Test in GPT Preview.

## Expected Behavior

- `echo ...` should return `status: "allowed"`
- `git push ...` should return `status: "blocked"`
- `rm -rf /` should return `status: "blocked"`
