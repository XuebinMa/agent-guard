# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`agent-guard` is an execution control layer for agent side effects. It sits between agent tool intent and real execution, evaluates calls against policy, applies validator and sandbox controls, and records auditable outcomes.

Today, the clearest proof point is shell-first execution control. The broader direction is side-effect execution control beyond shell, but the current adoption wedge is giving AI application and agent developers a real decision boundary before risky actions become real. Current version: 0.2.0-rc2.

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

Nine crates under `crates/`, layered bottom-up:

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
guard-verify              ← CLI: execution-receipt verification + host-boundary doctor
agent-guard-cli           ← CLI: interactive approval workflow (bin: agent-guard)
guard-hook                ← Claude Code PreToolUse hook adapter (bin: guard-hook)
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
- `DecisionCode`: normalized codes (DENIED_BY_RULE, PATH_TRAVERSAL, SENSITIVE_CONTENT_BLOCKED, ANOMALY_DETECTED, AGENT_LOCKED, etc. — the enum in `agent-guard-core/src/decision.rs` is the source of truth; don't hardcode a count)
- `GuardInput`: tool + JSON payload + Context (agent_id, session_id, trust_level, working_directory)
- `TrustLevel`: Untrusted (default), Trusted, Admin
- `PolicyMode`: ReadOnly, WorkspaceWrite, FullAccess
- `Sandbox` trait: `execute()`, `capabilities()`, `is_available()` — implemented per platform
- `Guard::sandbox_by_name(name)`: by-name backend resolution with truthful fallback (unknown → error, known-but-inactive → `"none"`; locked by GATE 5). Bindings expose it as `backend=` (Python kwarg) / trailing `backend` param (Node) on `execute`/`run`
- `Guard::check_content(text, &Context)` (feature `content`): scans host-supplied input text (prompts) against the top-level `input_content:` block; Mask returns the redacted text to the host
- `ExecutionProof`: Ed25519-signed cryptographic attestation of execution

## Feature Flags

Platform-specific sandbox features (off by default):
- `seccomp` — Linux seccomp-bpf (requires libseccomp)
- `landlock` — Linux Landlock filesystem isolation (kernel 5.13+)
- `macos-sandbox` — macOS Seatbelt/sandbox-exec
- `windows-sandbox` — Windows Job Objects
- `windows-appcontainer` — Windows AppContainer (compile-gated in the Windows CI job)

Other opt-in features: `content` (secret/PII detection on write/http payloads + input text). The Python and Node binding crates forward `seccomp`/`landlock` (and `macos-sandbox`) to the SDK so a feature-built binding can yield real isolation through the `backend` argument; default binding builds carry no sandbox feature.

## Policy System

Policies are YAML files parsed into `PolicyFile`. Key sections:
- `default_mode`: baseline permission mode
- `tools`: per-tool rules with pattern matching and conditions (evalexpr DSL); `http_request` rules may carry a `method:` constraint (case-insensitive; a rule with `method:` never matches a tool without a method)
- `input_content`: top-level content policy (`mode: block|mask|warn`, `detect:`) for host-supplied input text via `Guard::check_content` — top-level because an input is not a tool call
- `trust`: trust level overrides per agent/actor
- `anomaly`: rate limiting and Deny Fuse (locks agent after N denials in a time window)
- per-tool `content:` blocks: outbound content scanning (`write_file` content, `http_request` body)

## CI

GitHub Actions (`.github/workflows/ci.yml`) uses `./scripts/verify.sh` as the shared verification entrypoint for Rust, Python, Node, and docs/version checks. `verify.sh` honours env hooks used by the CI matrix legs: `AGENT_GUARD_PY_FRAMEWORKS` (pip-install real framework packages so `test_real_frameworks.py` runs instead of skipping), `AGENT_GUARD_PY_BUILD_FEATURES` (extra Cargo features for the maturin build, e.g. `seccomp`), and the binding tests read `AGENT_GUARD_EXPECT_BACKEND` (expected resolution for an explicit `linux-seccomp` request: `none` on default builds, `linux-seccomp` on feature-forwarded builds).

## Release Process

`CONTRIBUTING.md` § Releasing is the source of truth. Durable facts learned from cutting `0.2.0-rc2`:
- The version lives in ONE `workspace.package` field plus `=x.y.z` inter-crate pins, but `scripts/check-version-consistency.sh` enforces ~10 more markers (node `package.json` **and** `package-lock.json`, both `pyproject.toml`s, `plugin.json`, `marketplace.json`, plugin `package.json`, README badge — note the shields.io double-dash `0.2.0--rcN` — README/docs release links, docs/README title). Roll `CHANGELOG.md` `[Unreleased]` by hand.
- Prefer landing the bump as a normal PR and tagging the **main merge commit** afterwards — tagging a branch commit gets orphaned by squash-merge.
- Remote/cloud sessions **cannot push tags**: the session git proxy scopes pushes to the designated branch and returns 403 on tag refs. Hand the tag/Release step to the maintainer (GitHub UI "Draft a new release" creates tag + Release in one step).
- Historical version strings (old CHANGELOG headings, `docs/archive/`, era status markers) stay untouched on a bump; only current-facing markers move.

## Local Environment Gotchas (remote/cloud sessions)

- The container runs as **root**: `guard_init_fails_when_audit_file_unwritable` fails locally (asserts `/root/...` is unwritable) and the two seccomp stress tests (`test_stress_resource_*`) fail without real seccomp privileges. All pass in CI — verify against a clean `main` checkout before assuming a regression.
- `--all-features` needs `libseccomp-dev` (`apt-get install`) or linking fails with `unable to find library -lseccomp`; clippy passes without it (check doesn't link).
- Windows code can be type-checked WITHOUT a Windows host: `rustup target add x86_64-pc-windows-msvc` then `cargo check -p agent-guard-sandbox --features windows-appcontainer --target x86_64-pc-windows-msvc` (check doesn't link). The SDK with `--all-features` cross-fails on aws-lc-sys C code — that part is CI-only. Authoritative `windows`-crate signatures live in the vendored sources under `~/.cargo/registry/src/*/windows-0.52.0/src/Windows/`.
- The `agent-guard-plugin` drift test requires `packages/agent-guard-plugin/assets/coding-agent-outbound.yaml` to stay **byte-identical** to `presets/coding-agent-outbound.yaml` — re-copy after any preset edit, including comments.

## Testing Strategy

This is a security boundary, so the test is the specification of the boundary: write the failing test first, lock every closed bypass with a permanent regression, and never weaken a release gate to make CI green. The full philosophy, the layer map (unit / integration / gate / security-regression / parity / per-OS sandbox), and the local-vs-CI gap live in [docs/concepts/testing-strategy.md](docs/concepts/testing-strategy.md). Heavy crates carry their own scoped `CLAUDE.md` for local gotchas — see the scoped files under `crates/agent-guard-sdk/` (the Guard pipeline + integration test suite), `crates/agent-guard-sandbox/` (backend-selection invariants), `crates/agent-guard-validators/` (the security-critical bash classification tables), `crates/agent-guard-python/` (the PyO3 extension-module trap), and `crates/agent-guard-node/` (generated napi bindings + cross-language parity).

## Working Rules

- State assumptions when they matter. If multiple interpretations exist, surface them instead of choosing silently.
- Prefer the simplest implementation that satisfies the request. Avoid speculative abstractions, extra configurability, or unused flexibility.
- Keep changes surgical. Do not refactor unrelated code, reformat adjacent files, or remove pre-existing dead code unless asked.
- Clean up only what your change makes obsolete, such as unused imports or variables introduced by your edit.
- Define success in verifiable terms. When changing behavior, prefer tests or another concrete check before claiming completion.
