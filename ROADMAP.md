# Roadmap

This is the current, living forward-looking view for `agent-guard` as of
**0.2.0-rc1**. It distills the historical phase designs under
[`docs/archive/`](docs/archive/README.md) and the current code into one place
that separates *shipped* from *partial* from *planned*.

Two ground rules keep it honest:

- **It is not a delivery commitment.** Dates and ordering can change; treat
  "Next" and "Later" as intent, not promises.
- **Where the archived designs and the code disagree on status, this file
  follows the code.** The wedge claims stay narrow and truthful, the same as the
  rest of the docs. For the shipped detail behind each line, see
  [`CHANGELOG.md`](CHANGELOG.md).

## Where the boundary is today

The adoption wedge is a narrow execution-control runtime for three side-effect
surfaces: **shell / terminal**, **file write**, and **outbound mutation HTTP**.
Bash has the deepest validator path; the file and HTTP paths lean more on policy
matching than on runtime validation. See the "Current boundary note" in
[`docs/README.md`](docs/README.md) and the
[Framework Support Matrix](docs/reference/framework-support-matrix.md) for the
per-surface, per-language reality.

## Shipped (0.2.0-rc1)

- **Unified decision model** — `allow` / `deny` / `ask_for_approval` / `handoff`
  with normalised decision codes, exposed identically across the Rust SDK, the
  Node and Python bindings, and the Claude Code hook.
- **YAML policy engine** — prefix / regex / glob matching, `evalexpr` conditions,
  per-actor trust levels, and an anomaly "deny fuse" that rate-limits and locks
  an agent after repeated denials.
- **Bash execution control** — the deepest path: command-injection and
  path-traversal defenses, shell-separator awareness, transparent-wrapper
  unwrapping, and write-target collection for compound commands.
- **File-write + path validation** — workspace-confined normalisation with
  symlink-escape and `..`-traversal checks.
- **Outbound HTTP control** — the runtime distinguishes mutation methods
  (policy matching itself is still URL-centric — see *Partial*).
- **Sandbox backends, feature-gated and off by default** — a default build
  selects the noop backend and truthfully reports `"none"`. Opting into a
  feature enables the Linux seccomp backend (prototype/fallback), the macOS
  Seatbelt backend, or the Windows Job Object backend (with an experimental
  AppContainer backend).
- **Provenance** — opt-in Ed25519-signed execution receipts (they require an
  explicit signing key) plus append-only JSONL audit records; signed receipts
  are what carry cryptographic provenance.
- **Policy signing + verification** — a policy can be signed and its
  verification status surfaced through the bindings.
- **Observability** — Prometheus metrics and SIEM webhook export of audit
  records.
- **Bindings + adapters** — PyO3 (Python) and napi-rs (Node), each with
  LangChain-style and OpenAI-style adapters. Node adapters are validated against
  the real framework packages; Python adapters are beta.
- **Cross-language parity harness** — `tests/cross-language-parity/` with a
  scenario set that is the contract, gated by the CI `parity-e2e` job.
- **Claude Code plugin (preview)** — `npx agent-guard-plugin init` wires the
  `guard-hook` PreToolUse hook into Claude Code. See the
  [plugin guide](docs/guides/operations/claude-code-plugin.md).
- **Zero-config outbound preset** — [`presets/coding-agent-outbound.yaml`](presets/coding-agent-outbound.yaml).
- **Adoption tooling** — the `guard-verify doctor` host-boundary report and the
  check-vs-enforce migration guides.

## Partial / experimental today

These exist but are explicitly incomplete — do not describe them as finished.

- **Linux sandbox is a prototype/fallback wrapper.** The default build reports
  `"none"`; real isolation requires opting into the `seccomp` (or `landlock`)
  feature, and even then the Linux baseline is not a shipped production
  syscall-filtering enforcement path.
- **HTTP policy matching is URL-centric.** Method-awareness is a runtime
  distinction only; policy rules cannot yet match on HTTP method.
- **Windows AppContainer is experimental / opt-in.** Job Object is the default.
- **File and HTTP validators are thinner than bash.**
- **Content layer is an off-by-default PoC.** Secret/PII detection and redaction
  live behind a feature flag and are not wired into the main `Guard` pipeline;
  it is not a DLP engine.
- **Python adapters are beta** — no CI framework-version matrix yet.
- **The Claude Code plugin gates built-in tools** (`Bash`, `Write`, `Edit`,
  `WebFetch`); MCP tools (`mcp__*`) currently pass through ungated (upstream
  limitation).

## Next (near-term, 0.2.x)

Concrete items the current docs already frame as roadmap:

- **HTTP method-aware policy matching** — let rules distinguish `POST`/`PUT`/
  `DELETE` from `GET`, instead of URL-only matching.
- **Content detection on tool inputs** — scan prompts before they reach the
  provider, not only outbound effects.
- **Explicit sandbox backend selection in Python and Node** — today the binding
  picks the platform default.
- **Python CI framework-version matrix** — automate what is currently manual.
- **`reqwest` 0.12 / `rustls` 0.22 migration** — unblocks the RUSTSEC advisories
  currently `--ignore`d in the `cargo-audit` CI job.

## Later (v0.3.0+, draft)

From the Phase 8 design draft; explicitly out of 0.2.0 scope and subject to
change:

- **Hardware root of trust** — fold TPM 2.0 remote-attestation measurements into
  execution proofs.
- **Deeper Linux isolation** — Landlock filesystem access control plus namespace
  (`unshare`) isolation to complement seccomp.
- **OTLP / OpenTelemetry export** — a standard protocol path alongside today's
  JSONL and webhook export.
- **Stricter policy enforcement** — refuse unsigned or mismatched policy in a
  high-trust mode; move Windows toward AppContainer-by-default.
- **More adapters and presets** — additional framework surfaces (e.g. AutoGen)
  and policy templates beyond the outbound preset.

## Known debt

- **`reqwest` 0.12 / `rustls` 0.22 migration** — several ignored RUSTSEC
  advisories in CI are all reachable through the old `reqwest`/`rustls` chain and
  clear once this lands (tracked as a dedicated PR).
- **Global read access on macOS / Windows** is a v0.2 limitation of the sandbox
  capability model.

## How this maps to the archived phase docs

The archive uses non-sequential phase numbering; this is the current status
read from the code, not from the design docs' aspirations:

| Phase | Theme | Status |
| :--- | :--- | :--- |
| 1 | Core SDK & decision model | Shipped (v0.1.0) |
| 2 | Python binding & Linux sandbox | Shipped (v0.2.0-rc1) |
| 3 | Node binding, atomic reload, context-aware rules | Largely shipped; refinement ongoing |
| 6 | Receipts, unified capability model, SIEM | Mostly delivered in 0.2.0-rc1 |
| 8 | Trusted computing & deep isolation | Draft — targets v0.3.0 (see *Later*) |

The [`docs/archive/`](docs/archive/README.md) tree holds the original design and
strategy documents. Treat them as **history**: this file is the current
forward-looking view, and the archive is context for how it got here.
</content>
