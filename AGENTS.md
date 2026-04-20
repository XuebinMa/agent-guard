# AGENTS.md

This file provides guidance to Codex when working with this repository.

## Project Overview

`agent-guard` is a security runtime for AI agents. It intercepts tool calls, evaluates them against policy, applies validator and sandbox controls, and records auditable execution outcomes.

## Common Commands

```bash
cargo build --workspace --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
cargo fmt --all

cargo run -p agent-guard-sdk --example quickstart
cd crates/agent-guard-python && maturin develop
cd crates/agent-guard-node && npm run build
```

## Workspace Shape

The workspace is centered on six crates under `crates/`:

- `agent-guard-core`: policy, audit, and foundational types
- `agent-guard-validators`: command and path validation
- `agent-guard-sandbox`: platform sandbox implementations
- `agent-guard-sdk`: main integration layer
- `agent-guard-python`: Python bindings
- `agent-guard-node`: Node bindings

The main execution path is: policy check -> validator filter -> audit -> sandboxed execution.

## Working Rules

- State assumptions when they matter. If multiple interpretations exist, surface them instead of choosing silently.
- Prefer the simplest implementation that satisfies the request. Avoid speculative abstractions, extra configurability, or unused flexibility.
- Keep changes surgical. Do not refactor unrelated code, reformat adjacent files, or remove pre-existing dead code unless asked.
- Clean up only what your change makes obsolete, such as unused imports or variables introduced by your edit.
- Define success in verifiable terms. When changing behavior, prefer tests or another concrete check before claiming completion.
