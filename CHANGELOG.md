# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`cargo-release` automation rewrites the `[Unreleased]` heading at each release; do not delete it.

## [Unreleased]

## [0.2.0-rc2] - 2026-07-02

### Added
- **Method-aware HTTP policy rules** (#39, #105): an `http_request` rule can carry an optional `method:` constraint (case-insensitive; e.g. deny `POST` to a host while leaving `GET` allowed). Rules without `method:` behave exactly as before. A new `http` validator blocks `X-HTTP-Method-Override`-style header smuggling before the policy decision, locked by a `sec13` security regression; two cross-language parity scenarios verify identical decisions across Rust / Python / Node.
- **Content-layer input scanning** (#99, #106): a top-level `input_content:` policy block (same `mode: block | mask | warn` shape as per-tool `content:`) plus the feature-gated `Guard::check_content(text, &Context) -> ContentCheckOutcome { blocked, masked_text, labels }`, so a host can scan input text (e.g. a prompt) before it reaches the LLM provider. Mask hands the redacted text back to the host; findings audit as `ContentFinding` with tool label `"input"`, labels only.
- **Explicit sandbox backend selection** (#100, #107): `Guard::sandbox_by_name(name)` resolves a backend by its `sandbox_type()` string, exposed as a keyword-only `backend=` on the Python `execute`/`run` and a trailing `backend` parameter on the Node `execute`/`run`. Resolution is truthful (a backend that is not compiled in or not functional yields the `"none"` backend, never a false isolation claim; unknown names are hard errors) and locked by the new GATE 5 release gate.
- **Python real-framework CI matrix** (#101, #108): `tests/test_real_frameworks.py` exercises `wrap_langchain_tool` against real `langchain_core` `BaseTool`s (skips when the framework is absent), and the `python-framework-test` CI job matrixes it over the pinned `langchain-core >=0.3,<0.4` series plus unpinned latest via the new `AGENT_GUARD_PY_FRAMEWORKS` hook in `scripts/verify.sh`. Supersedes the manual `real_runtime_validation.py` script.
- **Contributor docs** (#98): `docs/concepts/testing-strategy.md` (the test-is-the-spec philosophy, layer map, local-vs-CI gap, definition of done), a live top-level `ROADMAP.md`, and scoped `CLAUDE.md` files for the five heavy crates; corrected the workspace crate count (nine, not seven) across the contributor docs.

### Fixed
- **AppContainer prototype compiles again under `windows` 0.52** (#80): ported the experimental Windows AppContainer sandbox off the pre-0.52 API surface (BOOL→`Result` returns, 4-arg `CreateAppContainerProfile`, relocated `SE_GROUP_ENABLED`, `HANDLE_FLAGS`), added the missing `Win32_System_IO` / `Win32_System_Pipes` / `Win32_System_SystemServices` feature gates, preserved the #48 error-handling intent (checked `GetExitCodeProcess`, `ERROR_ALREADY_EXISTS`-only profile tolerance, propagated reader-thread panics), and re-added the CI compile-gate on `windows-latest` so the feature can no longer break undetected.

### Changed
- **`cargo audit` runs unfiltered in CI** (#102, #104): dropped the six-entry blanket `--ignore` list — the `reqwest`/`rustls` migration it was waiting on had already shipped (`reqwest` 0.13 / `rustls` 0.23, `async-std` gone), so the advisories were unreachable and CI confirms the clean run.
- **`npx agent-guard-plugin init` (preview)**: one-command standalone setup for Claude Code under `packages/agent-guard-plugin`. Installs the `guard-hook` binary via `cargo install` (fail-soft if cargo is absent), writes the outbound policy to `~/.claude/agent-guard/policy.yaml` with audit redirected to a file (keeping the hook's stdout clean), and wires the `PreToolUse` hook into `~/.claude/settings.json` idempotently — preserving every other setting and hook. `--dry-run`, `--force`, `--binary-only` (for marketplace-plugin users), `--skip-binary`, and an `uninstall` command. Dependency-free; logic unit-tested with `node:test` including a no-drift check that the bundled policy stays byte-identical to `presets/coding-agent-outbound.yaml`.
- **Claude Code plugin (preview)**: agent-guard now installs as a Claude Code plugin. The repo doubles as a single-plugin marketplace (`.claude-plugin/marketplace.json` + `plugin.json`); `/plugin marketplace add XuebinMa/agent-guard` then `/plugin install agent-guard@agent-guard` registers a `PreToolUse` hook over `Bash`/`Write`/`Edit`/`WebFetch` that enforces the bundled outbound preset via `guard-hook`. The hook wrapper (`scripts/guard-hook-plugin.sh`) is fail-open (a missing binary or policy emits `allow`), honours `AGENT_GUARD_HOOK=off`, and keeps stdout reserved for the decision by routing audit records to stderr (or to a file with `audit: { output: file }`). See `docs/guides/operations/claude-code-plugin.md`.
- **Content layer (experimental, opt-in)**: credential / PII detection on outbound content (`write_file` content and `http_request` body) behind the off-by-default `content` feature. Add a `content:` block to any tool rule with `mode: block | mask | warn` and an optional `detect: [secrets, pii]` list. `block` denies (`SENSITIVE_CONTENT_BLOCKED`), `mask` rewrites findings to `[REDACTED:<label>]` before execution, `warn` executes unchanged; `mask`/`warn` emit a `ContentFinding` audit record carrying labels and counts only (never raw content). Run `cargo run -p agent-guard-sdk --example content_policy --features content`. See README § Content layer.
- `cargo-release` integration. New `release.toml` configures workspace-coordinated releases (shared version across all nine crates, single tag per workspace, manual push). See `CONTRIBUTING.md` § Releasing for the workflow.

## [0.2.0-rc1] - 2026-04-08

### Added
- **Windows Sandboxing**: Support for Low Integrity Level (Low-IL) and Job Objects.
- **AppContainer**: Experimental prototype for SID-based isolation (Opt-in).
- **macOS Seatbelt**: Formal integration with `sandbox-exec`.
- **Unified Capability Model (UCM)**: Decoupled security policy from platform implementation.
- **Provenance Receipts**: Ed25519-signed execution receipts for audit verification.
- **SIEM Integration**: Real-time audit log export via Webhooks.
- **Adoption Suite**: Capability Doctor and Migration Guides.

### Fixed
- CWE-78: Command injection vulnerabilities across all platforms via shlex-style escaping.
- CWE-22: Path traversal validator improvements.
- Fixed multiple memory safety and handle leak issues in Win32 implementation.
- Standardized API naming and result schemas.

## [0.1.0] - 2026-03-01
- Initial Alpha release with core SDK.
