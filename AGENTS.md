# AGENTS.md

This file provides guidance to Codex when working with this repository.

## Project Overview

`agent-guard` is an execution control layer for agent side effects. It sits between agent tool intent and real execution, evaluates calls against policy, applies validator and sandbox controls, and records auditable outcomes.

Today, the clearest proof point is shell-first execution control. The broader direction is side-effect execution control beyond shell, but the current adoption wedge is giving AI application and agent developers a real decision boundary before risky actions become real.

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
