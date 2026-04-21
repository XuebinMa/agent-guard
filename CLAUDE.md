# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

agent-guard is a multi-layered security runtime for AI agents. It intercepts tool calls (bash, file I/O, HTTP, custom tools), evaluates them against zero-trust YAML policies, executes in hardened OS sandboxes, and provides cryptographic proof of policy-compliant execution. Current version: 0.2.0-rc1.

## Build & Test Commands

```bash
# Canonical local verification entrypoint
./scripts/verify.sh full

# Rust-only verification path
./scripts/verify.sh rust
./scripts/verify.sh lint

# Build / test the Rust workspace without the PyO3 extension-module feature trap
cargo build --workspace --exclude agent-guard-python --all-features
cargo test --workspace --exclude agent-guard-python --all-features

# Test (single crate)
cargo test --package agent-guard-core

# Test (single test)
cargo test --package agent-guard-core --lib tests::test_policy_load

# Lint
cargo clippy --workspace --exclude agent-guard-python --all-features -- -D warnings

# Format check / fix
cargo fmt --all -- --check
cargo fmt --all

# Run an example
cargo run -p agent-guard-sdk --example quickstart

# Python binding (requires maturin; extension-module is opt-in)
cd crates/agent-guard-python && maturin develop --features extension-module

# Node binding
cd crates/agent-guard-node && npm run build
```

## Workspace Architecture

Seven crates under `crates/`, layered bottom-up:

```
agent-guard-core          ← foundational types, YAML policy engine, audit, attestation
  ↑
agent-guard-validators    ← bash command + path validation (destructive detection, traversal checks)
agent-guard-sandbox       ← multi-platform sandbox trait (seccomp, Seatbelt, Windows Job/AppContainer, noop)
  ↑
agent-guard-sdk           ← main integration point: Guard struct, anomaly detection, metrics, provenance, SIEM
  ↑
agent-guard-python        ← PyO3 bindings (maturin, abi3-py310)
agent-guard-node          ← napi-rs bindings
guard-verify              ← CLI verification and host-boundary diagnostics
```

## Current Product Reality

The current adoption wedge is a narrow execution-control runtime for:

- shell / terminal
- file write
- outbound mutation HTTP

The broader SDK already includes governance-oriented features such as policy signing, execution receipts, metrics, anomaly detection, and SIEM export. Do not describe the repository as a tiny shell-only layer, but do keep wedge claims narrow and truthful.

## Core Execution Pipeline

The `Guard` struct in agent-guard-sdk orchestrates: **Check → Filter → Audit → Sandbox**

1. Policy evaluation (`agent-guard-core`): YAML rules with prefix/regex/glob/DSL matching
2. Validator filtering (`agent-guard-validators`): command intent classification, path traversal checks
3. Audit logging: `AuditRecord` variants emitted at each stage, SIEM webhook export
4. Sandbox execution (`agent-guard-sandbox`): OS-level isolation per `PolicyMode`

## Key Types

- `Tool`: Bash, ReadFile, WriteFile, HttpRequest, Custom(CustomToolId)
- `GuardDecision`: Allow, Deny { reason }, AskUser { message, reason }
- `DecisionCode`: 16 codes (DENIED_BY_RULE, PATH_TRAVERSAL, ANOMALY_DETECTED, AGENT_LOCKED, etc.)
- `GuardInput`: tool + JSON payload + Context (agent_id, session_id, trust_level, working_directory)
- `TrustLevel`: Untrusted (default), Trusted, Admin
- `PolicyMode`: ReadOnly, WorkspaceWrite, FullAccess
- `Sandbox` trait: `execute()`, `capabilities()`, `is_available()` — implemented per platform
- `ExecutionProof`: Ed25519-signed cryptographic attestation of execution

## Feature Flags

Platform-specific sandbox features (off by default):
- `seccomp` — Linux seccomp-bpf (requires libseccomp)
- `macos-sandbox` — macOS Seatbelt/sandbox-exec
- `windows-sandbox` — Windows Job Objects
- `windows-appcontainer` — Windows AppContainer

## Policy System

Policies are YAML files parsed into `PolicyFile`. Key sections:
- `default_mode`: baseline permission mode
- `tools`: per-tool rules with pattern matching and conditions (evalexpr DSL)
- `trust`: trust level overrides per agent/actor
- `anomaly`: rate limiting and Deny Fuse (locks agent after N denials in a time window)

## CI

GitHub Actions (`.github/workflows/ci.yml`) uses `./scripts/verify.sh` as the shared verification entrypoint for Rust, Python, Node, and docs/version checks.
