# `@agent-guard/node`

`@agent-guard/node` now ships as both:

- a low-level N-API binding to the Rust SDK
- a high-level adapter layer for common Node agent integration patterns

This package is aimed at the Phase 1 adoption target in [`docs/architecture-and-vision.md`](../../docs/architecture-and-vision.md): make framework integration feel like a small wrapper, not a custom runtime rewrite.

## Supported Runtime Baseline

The repository CI validates the Node binding and framework wrappers against:

- Node `20`
- Node `22`
- `@langchain/core` `^0.3.75`
- `@openai/agents` `^0.8.3`

That is the published support floor for the current adapter layer.

## Runtime Validation

The adapter layer is now validated against real framework packages in this repository:

- `@langchain/core`
- `@openai/agents`

The Node test suite exercises real `DynamicTool` objects and real OpenAI Agents `tool()` definitions, not just mocked wrappers.

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

## Modes

- `check`: call `guard.check()` first, then run the original handler only if the decision is `allow`
- `enforce`: call `guard.execute()` and return the raw `ExecuteOutcome` by default
- `auto`: preflight with `guard.check()`; if the decision is `allow`, run the original handler, otherwise throw

## Quick Start

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

## LangChain-Style Tool Wrapper

```js
const { Guard, wrapLangChainTool } = require('@agent-guard/node')

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - "echo"
`)

const shellTool = {
  name: 'bash',
  description: 'Execute shell commands',
  async invoke(input) {
    return `ORIGINAL:${input}`
  },
}

wrapLangChainTool(guard, shellTool, {
  mode: 'enforce',
  resultMapper: (outcome) => outcome.output?.stdout ?? '',
})
```

## OpenAI Handler Wrapper

```js
const { Guard, wrapOpenAITool } = require('@agent-guard/node')

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  custom:
    calculator: {}
`)

const handler = wrapOpenAITool(
  guard,
  async (input) => ({ value: eval(input.expression) }),
  {
    tool: 'calculator',
    mode: 'check',
  }
)
```

## Result Mapping

`enforce` mode returns the raw `ExecuteOutcome` unless you provide `resultMapper`.

```js
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

## Demos

- `npm run demo:proof --prefix crates/agent-guard-node`
- `npm run demo:flow --prefix crates/agent-guard-node`
- [`demos/demo_langchain.js`](./demos/demo_langchain.js)
- [`demos/demo_openai_handler.js`](./demos/demo_openai_handler.js)
- [`demos/demo_check_vs_enforce.js`](./demos/demo_check_vs_enforce.js)
- [`demos/demo_multi_tool_flow.js`](./demos/demo_multi_tool_flow.js)
