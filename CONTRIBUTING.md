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

Nine crates under `crates/`, layered bottom-up:

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
agent-guard-cli           ← CLI: interactive approval workflow
guard-hook                ← Claude Code PreToolUse hook adapter
```

Cross-language e2e fixtures and runners live under [`tests/cross-language-parity/`](tests/cross-language-parity/).

## Verifying locally

The single canonical entrypoint:

```bash
./scripts/verify.sh full
```

This builds and tests the Rust workspace (with the PyO3 extension-module trap excluded), runs lint + format checks, builds and tests the Python binding through a temporary venv + maturin, builds and tests the Node binding, runs the docs link checker, and runs the cross-language parity comparator.

Narrower paths when you only changed one surface:

```bash
./scripts/verify.sh rust       # Rust workspace + lint
./scripts/verify.sh python     # PyO3 binding via maturin develop in a tmp venv
./scripts/verify.sh node       # napi-rs binding + Node tests
./scripts/verify.sh docs       # markdown link checker + content gates
```

CI reproduces each of these, plus the Linux/macOS/Windows sandbox-integration jobs and the cross-language e2e job. **All mandatory checks must be green before merge.** As of Sprint 4 the mandatory bar is 14 jobs: Rust workspace, lint, three sandbox-OS integrations, two Node version matrices, Python, docs, parity-e2e, cargo-deny, cargo-audit, SBOM, plus the bench-artifact (non-blocking).

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

## Subagent / multi-agent workflow

This repository is sometimes maintained with multiple parallel agents (worktree subagents, scheduled cron agents). The workflow has a few invariants you'll see in commit history:

- **Parallel work in worktrees.** Up to two subagents per Sprint task work in isolated git worktrees so their changes don't interfere. The worktrees live under `.claude/worktrees/`.
- **Conventional Commits + co-author trailer.** When an AI assistant authored a change, add the appropriate `Co-Authored-By:` trailer. The repository keeps the attribution.

External contributors are welcome to use these workflows or skip them entirely; the repository's only hard requirement is the verify + PR + green-CI loop above.

## Security

Vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues. The disclosure timeline (acknowledge ≤2 days, triage ≤7 days, fix-or-coordinate ≤14 days) is documented there.

For non-vulnerability security suggestions (defense in depth, hardening), open a regular GitHub issue.

## Releasing

Release engineering is centralized in `cargo-release` driven by the workspace-level [`release.toml`](release.toml).

```bash
cargo install cargo-release --locked   # one-time
cargo release <level>                  # dry-run — review the proposed diff + tag
cargo release <level> --execute        # commit version bump + create tag
git push origin main v<semver>         # push manually after review
```

`<level>` is one of `patch`, `minor`, `major`, `alpha`, `beta`, `rc`, or `release`. The configuration:

- Uses a **shared version** across all nine workspace crates so they always release together (matches the `version = "=0.2.0-rc1"` inter-crate pin in `Cargo.toml`).
- Creates **one tag per workspace** (`v<semver>`) rather than a tag per crate.
- **Skips `cargo publish`** for now (`publish = false` in `release.toml`) — flip to `true` when the crates are ready for crates.io.
- **Does not auto-push** — you push the tag explicitly so the release becomes visible only after a final review.
- **Does NOT roll `CHANGELOG.md`** automatically — `cargo-release`'s `pre-release-replacements` resolves paths per-crate, which would rewrite a workspace-level CHANGELOG nine times. Update `CHANGELOG.md` by hand before each release: rename the current `## [Unreleased]` heading to `## [<new-version>] — <date>` and add a fresh `## [Unreleased]` stub above it.

Recommended pre-release sequence:

1. Edit `CHANGELOG.md` — promote `[Unreleased]` to a versioned heading with the release date.
2. `cargo release <level>` — dry-run, review the proposed version bump.
3. `cargo release <level> --execute` — commit + tag.
4. `git push origin main v<semver>` — push when ready.

## Getting help

- **Open a GitHub Discussion** for design questions or "is this in scope?".
- **Open a GitHub Issue** for confirmed bugs or feature requests with reproductions.
- **Email security@** (see SECURITY.md) for vulnerabilities only.

Thank you for contributing — keep the bar high.
