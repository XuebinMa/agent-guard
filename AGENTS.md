# AGENTS.md

This file provides guidance to Codex when working with this repository.

## Project Overview

`agent-guard` is an execution control layer for agent side effects. It sits between agent tool intent and real execution, evaluates calls against policy, applies validator and sandbox controls, and records auditable outcomes.

Today, the clearest proof point is shell-first execution control. The broader direction is side-effect execution control beyond shell, but the current adoption wedge is giving AI application and agent developers a real decision boundary before risky actions become real.

## Common Commands

```bash
./scripts/verify.sh full
./scripts/verify.sh rust
./scripts/verify.sh lint

cargo build --workspace --exclude agent-guard-python --all-features
cargo test --workspace --exclude agent-guard-python --all-features
cargo clippy --workspace --exclude agent-guard-python --all-features -- -D warnings
cargo fmt --all -- --check
cargo fmt --all

cargo run -p agent-guard-sdk --example quickstart
cd crates/agent-guard-python && maturin develop --features extension-module
cd crates/agent-guard-node && npm run build
```

## Workspace Shape

The workspace is centered on seven crates under `crates/`:

- `agent-guard-core`: policy, audit, and foundational types
- `agent-guard-validators`: command and path validation
- `agent-guard-sandbox`: platform sandbox implementations
- `agent-guard-sdk`: main integration layer
- `agent-guard-python`: Python bindings
- `agent-guard-node`: Node bindings
- `guard-verify`: CLI diagnostics and verification tooling

The main execution path is: policy check -> validator filter -> audit -> sandboxed execution.

Current product reality to preserve in edits:

- the short-term wedge is shell, file write, and outbound mutation HTTP
- Bash still has the deepest validator path today
- the SDK already includes policy signing, execution receipts, metrics, anomaly detection, and SIEM export

## Working Rules

- State assumptions when they matter. If multiple interpretations exist, surface them instead of choosing silently.
- Prefer the simplest implementation that satisfies the request. Avoid speculative abstractions, extra configurability, or unused flexibility.
- Keep changes surgical. Do not refactor unrelated code, reformat adjacent files, or remove pre-existing dead code unless asked.
- Clean up only what your change makes obsolete, such as unused imports or variables introduced by your edit.
- Define success in verifiable terms. When changing behavior, prefer tests or another concrete check before claiming completion.
