# Contributing to agent-guard

`agent-guard` is the execution control layer that sits between an agent's tool intent and the side effect that intent produces. Because we are guarding *real* shell commands, file writes, and outbound HTTP, the bar for changes is higher than for a typical library: a regression here can let a malicious payload through.

This document is the 30-minute onboarding for that. Read it once, then keep [`README.md`](README.md), [`CLAUDE.md`](CLAUDE.md), and [`docs/README.md`](docs/README.md) open as you work.

## Quick links

- [Security policy](SECURITY.md) — how to report a vulnerability privately.
- [Documentation hub](docs/README.md) — concepts, guides, references.
- [Cross-language parity](docs/concepts/cross-language-parity.md) — what the Rust / Python / Node bindings must keep identical.
- [Threat model](docs/concepts/threat-model.md) — what the project actively defends against.

## Prerequisites

| Tool | Minimum | Why |
| :--- | :--- | :--- |
| Rust | **1.79** (MSRV) | Workspace policy, declared in `Cargo.toml`. |
| Node.js | 20 or 22 | Native bindings + adapter tests; matrixed in CI. |
| Python | 3.10+ (CI uses 3.12) | PyO3 bindings via `maturin` (abi3-py310). |
| `libseccomp-dev` | latest | Linux sandbox tests; `apt-get install` on Debian/Ubuntu. |

Optional but recommended for local supply-chain checks:

```bash
cargo install cargo-deny cargo-audit cargo-cyclonedx --locked
```

## Repository layout

Ten crates under `crates/`, layered bottom-up:

```
agent-guard-core          ← types, YAML policy engine, audit, attestation
  ↑
agent-guard-validators    ← bash command + path validators
agent-guard-sandbox       ← per-OS sandbox trait (seccomp, Seatbelt, JobObject, AppContainer, noop)
  ↑
agent-guard-sdk           ← Guard struct, anomaly detection, metrics, provenance, SIEM
  ↑
agent-guard-python        ← PyO3 bindings (maturin, abi3-py310)
agent-guard-node          ← napi-rs bindings
guard-verify              ← CLI: receipt verification + host-boundary doctor
agent-guard-broker        ← isolated, credential-bearing Git push transaction boundary
agent-guard-cli           ← CLI: interactive approval workflow
guard-hook                ← Claude Code PreToolUse hook adapter
```

Cross-language e2e fixtures and runners live under [`tests/cross-language-parity/`](tests/cross-language-parity/).

## Verifying locally

The single canonical entrypoint:

```bash
./scripts/verify.sh full
```

This builds and tests the Rust workspace (with the PyO3 extension-module trap
excluded), runs lint + format checks, builds and tests the Python binding through
a temporary venv + maturin, builds and tests the Node binding/plugin, and runs
the docs/version gates. It does **not** run the cross-language parity comparator
or reproduce the complete cross-platform CI matrix.

Narrower paths when you only changed one surface:

```bash
./scripts/verify.sh rust       # Rust workspace build + tests (no lint)
./scripts/verify.sh lint       # rustfmt --check + clippy -D warnings
./scripts/verify.sh python     # PyO3 binding via maturin develop in a tmp venv
./scripts/verify.sh node       # napi-rs binding + Node tests
./scripts/verify.sh docs       # markdown link checker + content gates
```

Cross-language parity is independently runnable locally after all bindings have
been rebuilt from the same tree. Follow the
[`parity-e2e` job](.github/workflows/ci.yml) to create a persistent venv, install
the Python module with `maturin develop --features extension-module`, build the
Node addon, then run from the repository root:

```bash
.venv/bin/python tests/cross-language-parity/compare.py
```

The comparator builds/runs the Rust runner. `verify.sh python` deletes its
temporary venv, so that path alone does not leave a module for the comparator.
Do not validate a new Rust tree against stale Python/Node bindings.

CI reproduces the local surfaces plus Linux seccomp/Landlock, macOS Seatbelt and
Windows Job Object integrations, real Python framework matrices and standalone
parity. **All mandatory checks must be green on the exact PR head before
merge.** The workflow includes Rust workspace, lint, four
sandbox integration jobs, two Node version-matrix legs, Python, two real Python
framework legs, two seccomp-forwarded binding legs (Python + Node), docs,
parity-e2e, cargo-deny, cargo-audit, SBOM, the authenticated local Git fixture,
and the non-blocking bench artifact. Strict container acceptance is a separate
native Linux gate, not a claim made by the host composition fixture.
The workflow is the operational source for this list; skips/unavailable
backends are not evidence that an OS isolation property passed.

For security delivery, also run strict all-target lint separately; `full` uses
Clippy without `--all-targets`:

```bash
cargo clippy --workspace --exclude agent-guard-python --all-features --all-targets -- -D warnings
```

## Branch + PR workflow

1. Branch off `main` with a Conventional-Commits-shaped name:
   - `feat/<slug>` for new functionality
   - `fix/<slug>` for bug fixes
   - `refactor/<slug>` for non-behavior-changing refactors
   - `perf/<slug>` for performance work
   - `test/<slug>` for test-only changes
   - `docs/<slug>` for documentation
   - `chore/<slug>` for dependency / tooling work
2. Make a single coherent commit per concern (squash-friendly).
3. Run `./scripts/verify.sh full` before pushing.
4. Open a PR via `gh pr create`. Body must include:
   - **Summary** — what changes and why, in 2-3 sentences.
   - **Test plan** — checklist of what was verified, including any added tests.
   - **Breaking change note** if applicable (mark commit with `!`).
5. Wait for CI. **Never merge with red checks.** If a check fails, push a fix-up commit; do not amend.

### Commit message format

[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>)!: <short summary, imperative, ≤72 chars>

<body explaining what and why, wrapped at 72 chars>

Co-Authored-By: <name> <email>
```

`!` after the scope marks a breaking change. Example: `fix(adapters)!: fail closed on invalid policy signatures in check mode`.

`<type>` is one of: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `chore`, `build`, `ci`.

`<scope>` is one of: `core`, `validators`, `sandbox`, `sdk`, `python`, `node`, `verify`, `adapters`, `deps`, `parity`, `security`. Pick whichever crate or area best matches the dominant change.

Sign off the trailer; if you used a coding assistant, add the appropriate `Co-Authored-By:` line.

## Code standards

### Rust

- Every `unsafe` block must have a `// Safety:` comment explaining the invariant that makes the unsafety sound.
- Avoid `unwrap()` in library code. Use `expect("...")` with a contextual message, or `?`. `unwrap()` in tests is fine.
- Run `cargo clippy --workspace --exclude agent-guard-python --all-features -- -D warnings` and `cargo fmt --all`.
- Don't add error handling, fallbacks, or validation for scenarios that can't happen — trust internal code and framework guarantees. Validate at boundaries.
- Default to writing no comments. Add a comment only when the *why* is non-obvious: a hidden constraint, a subtle invariant, a workaround for a specific bug. Remove comments that just restate code.
- Keep changes surgical. Don't refactor unrelated code in the same PR.

### Python (PyO3 bindings)

- Use `maturin develop --features extension-module` inside a venv to build for testing.
- Type stubs follow the binding's `pyo3::pyclass` definitions; keep them in sync.
- Adapter code in `python/agent_guard/` (langchain.py, openai.py, adapters.py) goes through `_decision_to_error_attrs` for any decision-shaped object.

### Node (napi-rs bindings)

- `index.d.ts` is generated by napi-rs from `src/lib.rs`; don't hand-edit it. Re-run `npm run build:debug` to regenerate.
- Adapter mode semantics for `enforce` / `check` / `auto` must match Python — see [adapter contract](docs/concepts/adapter-contract.md).

### Cross-language changes

If you touch any of these:

- `Decision` / `RuntimeDecision` / `RuntimeOutcome` shape
- `DecisionCode` enum
- `Guard.check` / `decide` / `run` / `execute` / `report_handoff_result` semantics
- adapter mode handling

Then **all three runners must change in the same PR** and `parity-e2e` must stay green. The parity scenarios under `tests/cross-language-parity/fixtures/scenarios.json` are the contract; if you're adding a new feature, add a scenario that exercises it.

### Tests

The full philosophy, layer map, and definition of done is in [Testing Strategy](docs/concepts/testing-strategy.md). The rules below are the minimum that every PR must meet.

- Unit tests live next to the code (in `src/tests.rs` or `mod tests` blocks).
- Integration tests live in `crates/<crate>/tests/`.
- Security regression cases go in `crates/agent-guard-sdk/tests/security_regression.rs` — patterns we've explicitly chosen to defend against.
- Don't mock the database or the policy engine — run against the real one.
- Preserve GATE 1–5 in `release_gate.rs`. GATE 3 can pass on an SDK refusal or
  return early without an active backend; it is not independent OS proof. Test
  resource containment by invoking the real backend directly with temporary,
  initially writable targets and an unsandboxed positive control.
- State shell scope accurately: the static grammar is Bash, Unix runners use
  `sh -c`, Windows noop/Job Object runners use `cmd.exe /C`, and hooks leave
  execution to the host. A finite regression corpus does not prove arbitrary
  program effects or all shell dialects. Default noop execution has no OS
  containment; same-user hooks are advisory. Neither separates credentials.
- Linux seccomp is opt-in native BPF in restricted modes; `FullAccess` skips
  its filter. It is not path-aware or a secret-read boundary. Keep known parser
  defects fixed or safely refused; do not claim `WorkspaceWrite` rejects every
  unknown executable.

The first strict broker/container profile remains planned. Its complete-runtime
and authenticated local-fixture gates are defined in the
[broker-first plan](docs/plans/broker-first-development-plan.md), with asset
permissions in [Credential isolation](docs/guides/operations/credential-isolation.md).
Those acceptance gates must cover file tools, MCP, hooks and approval input,
not just shell. A missing required Linux runtime must fail the dedicated gate,
not silently select advisory/noop. This narrows the first deployment claim
without expanding the API or removing existing platforms/transports. Current
CLI stdin confirmation, optional unsigned push receipts and `doctor` capability
reports are not proof of a trusted human or credential separation.

## Subagent / multi-agent workflow

This repository is sometimes maintained with multiple parallel agents (worktree subagents, scheduled cron agents). The workflow has a few invariants you'll see in commit history:

- **Parallel work in worktrees.** Up to two subagents per Sprint task work in isolated git worktrees so their changes don't interfere. The worktrees live under `.claude/worktrees/`.
- **Conventional Commits + co-author trailer.** When an AI assistant authored a change, add the appropriate `Co-Authored-By:` trailer. The repository keeps the attribution.

External contributors are welcome to use these workflows or skip them entirely; the repository's only hard requirement is the verify + PR + green-CI loop above.

## Security

Vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues. The disclosure timeline (acknowledge ≤2 days, triage ≤7 days, fix-or-coordinate ≤14 days) is documented there.

For non-vulnerability security suggestions (defense in depth, hardening), open a regular GitHub issue.

## Releasing

Release preparation uses the atomic multi-language
[`bump-version.sh`](scripts/release/bump-version.sh) tool. Registry writes belong
to [the tag-triggered workflow](.github/workflows/release.yml), not cargo-release.
[`release.toml`](release.toml) retains shared-version/tag metadata with
`publish = false` and `push = false`; do not use cargo-release alone to update
Python, Node, plugin and documentation markers.

- All ten workspace crates share one version (matches the `version = "=0.2.7"` inter-crate pin in `Cargo.toml`).
- The workflow publishes eight public Rust crates in dependency order using
  `cargo publish --locked`, Python wheels as `agent-guard-python`, and the npm
  installer as `agent-guard-plugin`. The Python/Node Cargo binding crates have
  `publish = false`; the Node binding is not currently published to npm.
- A release has one workspace tag, not a tag per crate. Do not tag a PR branch:
  squash merging would leave that tag on an untested/unprotected branch commit.
- Promote `[Unreleased]` to a dated versioned CHANGELOG heading by hand and add a
  fresh `[Unreleased]` heading. Keep historical release notes unchanged.

Required sequence:

1. Run `scripts/release/bump-version.sh` with the chosen new version. Review its
   complete source-marker and exact dependency-pin diff, including Cargo.lock.
   Keep **published** install/version markers unchanged until publication is
   verified; source version and latest available release may intentionally differ.
2. Update CHANGELOG, run `./scripts/verify.sh full` and submit the preparation
   through a normal PR. Require successful cross-platform CI on its exact head.
3. Merge only that verified head. Then wait for a successful `ci.yml` **push** run
   on the exact final `main` merge SHA, including the version preparation.
4. Recheck that `origin/main` still points at that SHA. Only then create/push the
   matching version tag (or create it through a GitHub Release). The release gate
   requires `tag commit == GITHUB_SHA == current origin/main` and the successful
   main push CI; a previous green PR run or older main commit is insufficient.
5. The workflow reruns full preflight and supply-chain gates, publishes Rust
   crates, and only then uploads PyPI wheels and publishes the npm plugin. Wheel
   builds may run in parallel, but uploads cannot claim a complete release before
   the Rust publication succeeds. Respect configured environment approvals.
6. Verify all eight Rust crate versions, all supported Python wheel platforms,
   and the npm plugin. Test exact-version `--locked` installation before updating
   published install markers or advertising the release. Correct security
   advisories only with versions actually available; do not label an unreleased
   branch as a released fix.

## Getting help

- **Open a GitHub Discussion** for design questions or "is this in scope?".
- **Open a GitHub Issue** for confirmed bugs or feature requests with reproductions.
- **Email security@** (see SECURITY.md) for vulnerabilities only.

Thank you for contributing — keep the bar high.
