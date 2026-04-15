# ChatGPT Actions Integration

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Practical Integration Guide |
| **Audience** | Developers, GPT Builders |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [User Manual](user-manual.md), [Secure Shell Tools](secure-shell-tools.md), [Check vs Enforce](check-vs-enforce.md) |

---

This guide shows the most practical way to try `agent-guard` with ChatGPT today:

`Custom GPT` -> `GPT Action` -> `your HTTP API` -> `agent-guard` -> `real tool`

The key idea is simple:

ChatGPT itself does not run your local shell tool directly. Instead, a Custom GPT calls your API through an Action, and your API uses `agent-guard` before it executes anything risky.

---

## 1. What Is Possible Today

As of April 14, 2026, the supported ChatGPT path is:

- create a Custom GPT in the web editor
- configure an Action using an OpenAPI schema
- point that Action at your own HTTP service
- let your service apply `agent-guard` before running the underlying tool

Important platform constraints from OpenAI's official documentation:

- GPT building/editing is done in the web editor
- GPTs can use either **Apps** or **Actions**, but not both at the same time
- Actions are defined by authentication plus an OpenAPI schema
- workspace admins can restrict allowed action domains
- public GPTs with actions must include a privacy policy URL

Official references:

- OpenAI Help: `Creating and editing GPTs`
- OpenAI Help: `Configuring actions in GPTs`
- OpenAI Platform Docs: `Actions`

---

## 2. Architecture

Use this shape:

```text
ChatGPT Custom GPT
    |
    v
GPT Action (OpenAPI)
    |
    v
Your Node HTTP service
    |
    v
agent-guard wrapper
    |
    v
real tool / sandboxed execution
```

That means `agent-guard` sits on the server side, where you control:

- the policy
- the tool wrapper
- the execution mode
- the audit and receipt behavior

---

## 3. Best First Use Case

The best first ChatGPT Action to protect is a shell-like or other high-risk tool.

Recommended example:

- safe command: `echo hello`
- risky command: `git push origin main`
- clearly dangerous command: `rm -rf /`

Why this works well:

- easy to explain
- easy to see the difference between allowed and blocked
- shows the value of `ask` and `deny`

---

## 4. Recommended Mode

For a shell Action, use:

- `mode: "enforce"`

That way the Action does not just check policy and then call your old shell handler. Instead, it moves execution into the guarded path and lets `agent-guard` select the sandbox.

For non-shell Actions such as search, internal RPC, or calculator-like helpers, use:

- `mode: "check"`

---

## 5. Example Assets In This Repository

A minimal ChatGPT Actions example is provided here:

- [Example README](../../../crates/agent-guard-node/examples/chatgpt-actions/README.md)
- [Example policy](../../../crates/agent-guard-node/examples/chatgpt-actions/policy.yaml)
- [Example server](../../../crates/agent-guard-node/examples/chatgpt-actions/server.js)
- [Example OpenAPI schema](../../../crates/agent-guard-node/examples/chatgpt-actions/openapi.yaml)

This example is intentionally small so a new user can see the pattern quickly.

---

## 6. Step-by-Step Setup

## Step 1: Start the Example Server

From the repository root:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:chatgpt-actions --prefix crates/agent-guard-node
```

That starts a local HTTP server with:

- `GET /health`
- `POST /run-shell`

---

## Step 2: Make It Reachable From ChatGPT

For a real Action test, ChatGPT needs a reachable URL.

Typical choices:

- deploy the example server to a public HTTPS host
- or tunnel your local machine using a temporary HTTPS endpoint

Your final Action base URL must match the `servers` section in the OpenAPI schema you import into ChatGPT.

---

## Step 3: Open the GPT Builder

Go to:

- `https://chatgpt.com/gpts/editor`

Then:

1. create a new GPT
2. switch to the configuration view if needed
3. open the **Actions** section
4. choose **Create new action**

---

## Step 4: Import the OpenAPI Schema

Use the example schema in:

- [openapi.yaml](../../../crates/agent-guard-node/examples/chatgpt-actions/openapi.yaml)

You can:

- paste it directly
- or host it and import by URL

If you change the server base URL, update the schema first.

---

## Step 5: Configure Authentication

For the local demo, the example schema uses:

- no authentication

For real deployments, choose one of the supported GPT Action auth models:

- none
- API key
- OAuth

If you want a quick internal proof-of-concept, API key auth is often the simplest next step.

---

## Step 6: Test In GPT Preview

Try prompts like:

- `Run echo hello from ChatGPT`
- `Run git push origin main`
- `Run rm -rf /`

Expected outcome:

- `echo hello from ChatGPT` should succeed
- `git push origin main` should return a blocked or approval-required result
- `rm -rf /` should be blocked

---

## 7. What The Server Is Doing

The example server:

1. loads `policy.yaml`
2. creates a `Guard`
3. wraps a shell-like tool with `wrapOpenAITool()`
4. exposes an HTTP endpoint
5. returns structured JSON for both allowed and blocked outcomes

This gives you a clean seam between:

- ChatGPT-facing API
- internal policy enforcement
- actual execution

---

## 8. Response Design Recommendation

For Actions, prefer returning clear JSON instead of raw thrown stack traces.

Recommended response shape:

```json
{
  "status": "blocked",
  "error": "AgentGuardAskRequiredError",
  "decision": "ask_user",
  "code": "AskRequired",
  "message": "Confirmation required..."
}
```

This makes GPT behavior more understandable and easier to prompt around.

---

## 9. Safety Notes

- Do not expose a shell Action publicly with a broad policy.
- Keep the allowlist intentionally small.
- Start in a development or staging environment.
- Prefer a dedicated workspace directory instead of unrestricted host paths.
- Use `demo_transparency` or `doctor` to understand your real sandbox boundary first.

---

## 10. When To Use API Instead Of ChatGPT Actions

If you need deeper tool orchestration, more control over runtime, or a fully app-owned UI, use the OpenAI API / Agents SDK directly instead of starting inside ChatGPT.

Use ChatGPT Actions when your goal is:

- fastest interactive demo
- internal proof-of-concept
- GPT-based workflow trial without building a full chat frontend

---

## 11. Recommended Next Read

After this guide:

1. read [Secure Shell Tools](secure-shell-tools.md)
2. read [Check vs Enforce](check-vs-enforce.md)
3. adapt the example policy to your real tool surface
