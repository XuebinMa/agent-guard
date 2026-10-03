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
- use `auto` when the exact `bash` tool should execute through the Guard and
  non-shell tools should use the unified runtime lifecycle
- or use raw `decide()` / `run()` when you want the normalized runtime decisions directly

## Why Start Here

- Node currently has the clearest quickstart and demo path in the repository
- Node adapters are validated against real `@langchain/core` and `@openai/agents` packages
- the side-effect wedge demo is easiest to understand and prove from this package

## Supported Runtime Baseline

The repository CI validates the Node binding and framework wrappers against:

- Node `20`
- Node `22`
- `@langchain/core` `^1.2.3`
- `@openai/agents` `^0.8.3`

That is the tested support floor for the current adapter layer.

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
- `auto`: the exact tool ID `bash` uses `guard.execute()`; non-shell tool IDs
  use `guard.run()`, invoke the original handler only for a `handoff`, and
  submit a one-shot terminal report before returning. Guard-owned WriteFile or
  mutating HTTP outcomes can execute without invoking the host handler.

If a host action finishes but its handoff report is rejected, the adapter
throws `AgentGuardExecutionError` rather than returning an apparently complete
result. The error carries `hostActionCompleted: true`, the `hostResult`, and a
warning not to retry automatically. It also carries `requestId` and the
attempted `handoffReport` so an operator can reconcile reporting without
rerunning the action. If both the host action and its report fail, the original host error is
preserved with the reporting error attached as `agentGuardReportError`.

Shell-like custom IDs such as `shell`, `terminal`, `sh`, `zsh`, `cmd`,
`powershell`, and `pwsh` are not silently treated as Bash or handed back to the
host in `auto`: the adapter raises `UnsupportedShellAlias`. Map a real
Bash-backed framework tool to `tool: "bash"`, or deliberately choose an
explicit mode.

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
  JSON.stringify({ path: '/workspace/summary.txt', content: shellOutcome.output.stdout.trim() }),
  { workingDirectory: '/workspace' }
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
- the binding uses the SDK default sandbox selection, or an explicit backend name passed as the fourth argument to `execute` / `run` (e.g. `guard.execute(tool, payload, options, 'none')`); a backend that is not compiled in or not functional resolves truthfully to `'none'`, and an unknown name rejects
- to get real isolation through the backend argument, build the addon with the matching feature forwarded, e.g. `npm run build:debug -- --features seccomp` (requires libseccomp on Linux); the default build carries no sandbox feature
- if the default sandbox falls back to `NoopSandbox`, the policy gate still runs but OS-level isolation is not equivalent
- Bash still has the deepest validator path today; file and HTTP controls remain more policy-centric than Bash validation

## Dependency audit posture

`@agent-guard/node` is **not currently published to npm**; build it from this
repository as described in the root README. The package has no runtime npm
dependencies. Its declared dev dependencies (`@langchain/core`,
`@openai/agents`, `@napi-rs/cli`, `zod`) build the binding and exercise
framework compatibility; they are not part of the runtime dependency tree.

Consequently:

- **Dev-only advisories do not gate releases.** They are reachable only from
  test/build tooling, not the runtime tree. As of 2026-10-02 the checked-in
  lockfile reports four transitive dev-only findings (three moderate, one high)
  through framework/build dependencies; `npm audit --omit=dev` reports zero.
  Keep them patched when compatible upstream releases are available.
- **Production dependencies are gated in CI.** The Node CI job runs `npm audit --omit=dev --audit-level=moderate`. Because there are no runtime dependencies today, this is currently empty/clean; if a real runtime dependency is ever added, a `moderate`+ advisory there fails CI.

To reproduce locally:

```bash
cd crates/agent-guard-node
npm audit --omit=dev --audit-level=moderate   # production tree — must be clean
npm audit                                       # full tree — dev advisories are informational
```

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
