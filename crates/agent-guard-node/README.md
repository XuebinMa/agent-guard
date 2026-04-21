# `@agent-guard/node`

`@agent-guard/node` is the fastest way to put `agent-guard` in front of Node-based agent tools and handlers.

Use it when your agent is about to cause a real side effect and you want a decision at the execution boundary:

- execute it through `agent-guard`
- deny it
- ask for approval
- or hand it back to the host runtime

Today, the strongest short-term wedge is a narrow multi-side-effect runtime:

- shell / terminal
- file write
- outbound mutation HTTP

That makes this package a good fit for code agents and other Node runtimes where risky actions should not flow straight from model output into the real host environment.

## What Ships In This Package

This package includes both:

- a low-level N-API binding to the Rust SDK
- a high-level adapter layer for common Node agent integration patterns

You can adopt it incrementally:

- use `check` to put a policy gate in front of an existing tool handler
- use `enforce` for shell-like tools when you want `agent-guard` to own the execution path
- use `auto` as a migration bridge when you want a light preflight gate first
- or use raw `decide()` / `run()` when you want the normalized runtime decisions directly

## Why Start Here

- Node currently has the clearest quickstart and demo path in the repository
- Node adapters are validated against real `@langchain/core` and `@openai/agents` packages
- the side-effect wedge demo is easiest to understand and prove from this package

## Supported Runtime Baseline

The repository CI validates the Node binding and framework wrappers against:

- Node `20`
- Node `22`
- `@langchain/core` `^0.3.75`
- `@openai/agents` `^0.8.3`

That is the published support floor for the current adapter layer.

## What You Get

- Raw `Guard` APIs: `check()`, `execute()`, `decide()`, `run()`, `reload()`, `policyVersion()`
- Adapter factory: `createGuardedExecutor()`
- LangChain-style object wrapper: `wrapLangChainTool()`
- OpenAI handler wrapper: `wrapOpenAITool()`
- Typed adapter errors:
  - `AgentGuardDeniedError`
  - `AgentGuardAskRequiredError`
  - `AgentGuardExecutionError`
- Signed-policy load path:
  - `Guard.fromSignedYaml()`
  - `Guard.fromSignedYamlFile()`
- Policy verification metadata:
  - `guard.policyVerification()`
  - `decision.policyVerificationStatus`
  - `executeOutcome.policyVerificationStatus`

## Mode Selection

- `check`: call `guard.check()` first, then run the original handler only if the decision is `allow`
- `enforce`: call `guard.execute()` and return the execution outcome instead of running the original handler
- `auto`: preflight with `guard.check()`; if the decision is `allow`, run the original handler, otherwise throw

If you want the normalized wedge vocabulary directly, start with `decide()` and `run()`. If you are integrating through existing handler wrappers, `enforce` is still strongest on shell-like tools today.

## Quick Start

This example shows the shell-first path. The original handler is bypassed in `enforce` mode, and `agent-guard` owns the execution path.

```js
const { Guard, wrapOpenAITool } = require('@agent-guard/node')

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - "echo"
`)

const guardedShell = wrapOpenAITool(
  guard,
  async () => {
    throw new Error('This handler is bypassed in enforce mode')
  },
  {
    tool: 'bash',
    mode: 'enforce',
    resultMapper: (outcome) => outcome.output?.stdout ?? '',
  }
)
```

For the shortest runnable example, see [examples/quickstart](./examples/quickstart/README.md).

## Runtime Wedge Example

This example uses the raw runtime APIs and crosses shell, file write, and outbound mutation HTTP in one flow.

```js
const { Guard } = require('@agent-guard/node')

const guard = Guard.fromYaml(policyYaml)

const shellDecision = guard.decide('bash', JSON.stringify({ command: 'echo summary:ready' }))
const shellOutcome = await guard.run('bash', JSON.stringify({ command: 'echo summary:ready' }))

const fileDecision = guard.decide(
  'write_file',
  JSON.stringify({ path: '/workspace/summary.txt', content: shellOutcome.output.stdout.trim() })
)

const httpDecision = guard.decide(
  'http_request',
  JSON.stringify({ method: 'POST', url: 'http://127.0.0.1:3000/publish', body: 'summary:ready' })
)
```

For the clearest runnable version, see [`demos/demo_side_effect_wedge.js`](./demos/demo_side_effect_wedge.js).

## API-Like Tool Example

For non-shell tools, `check` is often the right first step. That keeps your original handler while still adding a pre-execution decision point.

```js
const {
  Guard,
  wrapOpenAITool,
  AgentGuardDeniedError,
} = require('@agent-guard/node')

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  custom:
    web_search: {}
`)

const searchHandler = wrapOpenAITool(
  guard,
  async (input) => ({ ok: true, query: input.query }),
  {
    tool: 'web_search',
    mode: 'check',
    trustLevel: 'Trusted',
  }
)

async function main() {
  try {
    const result = await searchHandler({ query: 'agent-guard' })
    console.log(result)
  } catch (error) {
    if (error instanceof AgentGuardDeniedError) {
      console.error('Blocked by policy:', error.policyVersion, error.code)
    }
  }
}

main()
```

## Runtime Validation

The adapter layer is validated against real framework packages in this repository:

- `@langchain/core`
- `@openai/agents`

The Node test suite exercises real `DynamicTool` objects and real OpenAI Agents `tool()` definitions, not just mocked wrappers.

## Practical Boundary Notes

- the raw runtime can now own execution for shell, file write, and outbound mutation HTTP
- adapter `enforce` remains the strongest shell-first path in the higher-level wrappers
- if your host runtime adds its own execution boundary, you can combine that with `agent-guard` policy decisions
- the binding currently uses the SDK default sandbox selection internally; it does not yet expose an explicit sandbox-selection API
- if the default sandbox falls back to `NoopSandbox`, the policy gate still runs but OS-level isolation is not equivalent
- Bash still has the deepest validator path today; file and HTTP controls remain more policy-centric than Bash validation

## Demos

- `npm run demo:quickstart --prefix crates/agent-guard-node`
- `npm run demo:wedge --prefix crates/agent-guard-node`
- `npm run demo:proof --prefix crates/agent-guard-node`
- `npm run demo:flow --prefix crates/agent-guard-node`
- [`demos/demo_side_effect_wedge.js`](./demos/demo_side_effect_wedge.js)
- [`demos/demo_langchain.js`](./demos/demo_langchain.js)
- [`demos/demo_openai_handler.js`](./demos/demo_openai_handler.js)
- [`demos/demo_check_vs_enforce.js`](./demos/demo_check_vs_enforce.js)
- [`demos/demo_multi_tool_flow.js`](./demos/demo_multi_tool_flow.js)
