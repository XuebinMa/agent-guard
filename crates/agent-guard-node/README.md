# `@agent-guard/node`

`@agent-guard/node` is the fastest way to put `agent-guard` in front of Node-based agent tools and handlers.

Use it when your agent is about to cause a real side effect and you want a decision at the execution boundary:

- allow the call
- block it
- ask for approval
- or move execution into `agent-guard` itself

Today, the strongest proof point is shell / terminal tooling. That makes this package a good fit for code agents, shell-enabled assistants, and other Node runtimes where risky commands should not flow straight from model output into the real host environment.

## What Ships In This Package

This package includes both:

- a low-level N-API binding to the Rust SDK
- a high-level adapter layer for common Node agent integration patterns

You can adopt it incrementally:

- use `check` to put a policy gate in front of an existing tool handler
- use `enforce` for shell-like tools when you want `agent-guard` to own the execution path
- use `auto` as a migration bridge when you want a light preflight gate first

## Why Start Here

- Node currently has the clearest quickstart and demo path in the repository
- Node adapters are validated against real `@langchain/core` and `@openai/agents` packages
- the shell-first story is easiest to understand and prove from this package

## Supported Runtime Baseline

The repository CI validates the Node binding and framework wrappers against:

- Node `20`
- Node `22`
- `@langchain/core` `^0.3.75`
- `@openai/agents` `^0.8.3`

That is the published support floor for the current adapter layer.

## What You Get

- Raw `Guard` APIs: `check()`, `execute()`, `reload()`, `policyVersion()`
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

If the tool is really a shell tool, start by evaluating `enforce` first. That is where the package most clearly acts as an execution control layer instead of a policy-only wrapper.

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

- the strongest current `enforce` path is shell / Bash execution
- many non-shell tools are best treated as `check` surfaces first
- if your host runtime adds its own execution boundary, you can combine that with `agent-guard` policy decisions

## Demos

- `npm run demo:quickstart --prefix crates/agent-guard-node`
- `npm run demo:proof --prefix crates/agent-guard-node`
- `npm run demo:flow --prefix crates/agent-guard-node`
- [`demos/demo_langchain.js`](./demos/demo_langchain.js)
- [`demos/demo_openai_handler.js`](./demos/demo_openai_handler.js)
- [`demos/demo_check_vs_enforce.js`](./demos/demo_check_vs_enforce.js)
- [`demos/demo_multi_tool_flow.js`](./demos/demo_multi_tool_flow.js)
