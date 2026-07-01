# CLAUDE.md — agent-guard-node

Scoped guidance for the napi-rs binding. This **adds** to the root
[`CLAUDE.md`](../../CLAUDE.md); it does not repeat it.

## Crate shape

A napi-rs binding compiled to a native `.node` addon and published as
`@agent-guard/node` (`main: runtime.js`, `types: runtime.d.ts`, napi name
`agent_guard_node`). `src/lib.rs` wraps the SDK's `Guard` (`check` / `execute`)
and the decision types, plus the LangChain-style / OpenAI-style adapters.

## Generated code — don't hand-edit

`napi build` generates the native binding loader and its TypeScript typings
(`index.d.ts`) from `src/lib.rs`. Do **not** hand-edit generated typings — change
the `#[napi]` surface in `src/lib.rs` and re-run `npm run build:debug` to
regenerate. `build:debug` is the debug build; `build` is the `--release` build.
Both compile the Rust crate, so they need the Rust toolchain.

## This binding is a parity runner

`agent-guard-node` is one of the three cross-language parity surfaces. The napi
`Decision` / `RuntimeDecision` structs in `src/lib.rs` mirror the core decision
shape field-for-field (message, code, matched rule, ask prompt, policy version,
policy verification status). A change to that shape, to `DecisionCode`, or to
`check` / `decide` / `run` / `execute` / adapter-mode semantics is only correct
if the Rust core and the Python binding change with it and the parity scenarios
still pass — see [Cross-Language Parity](../../docs/concepts/cross-language-parity.md),
[Adapter Contract](../../docs/concepts/adapter-contract.md), and the parity
section of the [Testing Strategy](../../docs/concepts/testing-strategy.md).
Adapter mode handling (`enforce` / `check` / `auto`) must match Python exactly.

## Dev dependencies are not shipped

`@langchain/core`, `@openai/agents`, and `zod` are **devDependencies** used only
by the framework-parity tests. The published surface is the compiled `.node`
addon with **no runtime npm dependencies**. That is why CI audits the production
tree only (`npm audit --omit=dev`): advisories in those dev-only agent SDKs are
accepted and must not gate a release. Do not promote them to runtime deps.

## Testing

`npm test` runs `test-adapters.js`, `test-frameworks.js`, and `test.js`. Prefer
the wrapper, which builds first:

```bash
./scripts/verify.sh node    # napi build:debug + node tests + plugin tests
```

CI matrixes this across Node 20 and 22. Cross-language obligations are in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).
</content>
