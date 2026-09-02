# Roadmap

This is the current, living forward-looking view for `agent-guard` as of
**0.2.0**. It distills the historical phase designs under
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

The codebase supports three side-effect surfaces: **shell / terminal**, **file
write**, and **outbound mutation HTTP**. Product development is narrower: exact
authorization for one broker-executed Git push transaction. Bash has the deepest
validator path; the file and HTTP paths lean more on policy matching than on
runtime validation. See the "Current boundary note" in
[`docs/README.md`](docs/README.md) and the
[Framework Support Matrix](docs/reference/framework-support-matrix.md) for the
per-surface, per-language reality.

## Shipped (0.2.0)

- **Unified decision model** — `allow` / `deny` / `ask_for_approval` / `handoff`
  with normalised decision codes, exposed identically across the Rust SDK, the
  Node and Python bindings, and the Claude Code hook.
- **YAML policy engine** — prefix / regex / glob matching, `evalexpr` conditions,
  per-actor trust levels, and an anomaly "deny fuse" that rate-limits and locks
  an agent after repeated denials.
- **Bash execution control** — the deepest path: command-injection and
  path-traversal defenses, shell-separator awareness, transparent-wrapper
  unwrapping, write-target collection for compound commands, and structured
  recognition that maps recognized direct `git push` forms, explicitly modeled
  wrappers, and plumbing-level `git send-pack` calls to one policy subject.
  Force, mirror, delete, and destructive refspec shorthand are classified
  before raw policy matching. Adjacent standalone Git argv tokens under an
  unknown outer command are governed conservatively and recorded as unverified
  candidates, not asserted executions.
- **File-write + path validation** — workspace-confined normalisation with
  symlink-escape and `..`-traversal checks.
- **Outbound HTTP control** — the runtime distinguishes mutation methods, and
  policy rules are method-aware: a rule can carry a `method:` constraint, backed
  by an http validator that blocks method-override-header smuggling.
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
- **Windows AppContainer is experimental / opt-in.** Job Object is the default.
- **File and HTTP validators are thinner than bash.**
- **Content layer is off-by-default and spike-grade.** Behind the `content`
  feature it scans `write_file` content, `http_request` body, and input text
  (`Guard::check_content`); the detector set is named-patterns + entropy and
  regex + Luhn — not a DLP engine.
- **Python adapters are beta** — no CI framework-version matrix yet.
- **The Claude Code plugin gates built-in tools** (`Bash`, `Write`, `Edit`,
  `WebFetch`); MCP tools (`mcp__*`) currently pass through ungated (upstream
  limitation).
- **The hook is advisory and fail-open.** It does not own credentials or
  execution, so an agent able to avoid the host hook can avoid this check.
- **Shell argv does not prove arbitrary program semantics.** Dedicated parsers
  unwrap supported launcher forms, while conservative embedded-Git detection
  may reject bare words used as data and still cannot prove what an unknown
  program will execute. The credential-isolated broker is the class-level
  boundary.
- **The local approval ledger is not authenticated.** Request binding and
  execution-time policy revalidation close accidental/stale approval errors;
  adversarial isolation still requires a separate broker process.

## One target: broker-enforced Git push

The next product milestone is deliberately one vertical path, not another
generic security platform. Success means the agent cannot perform a remote Git
mutation without the Guard executing the exact, approved transaction.

1. **Exact intent** — normalize repository identity, resolved remote URL,
   refspecs, old/new object IDs, force/lease/mirror/delete semantics, and the
   relevant Git options into one immutable `GitPushIntent`.
2. **Exact preview** — show the human the remote, branch/tag changes, commits,
   deletions, and destructive semantics that the authorization will cover.
3. **One-use authorization** — issue a short-lived grant bound to an intent
   hash, nonce, policy hash, actor, and expiry; consume it atomically.
4. **Broker-owned execution** — keep remote credentials outside the agent
   process. Immediately before pushing, re-read local refs, query the remote,
   re-evaluate policy, and reject any drift from the approved intent.
5. **Receipt** — sign the final attempted/observed transaction and its outcome,
   clearly distinguishing a Guard-witnessed push from a host-reported claim.

The first supported shape is intentionally small: GitHub, one repository, one
branch, ordinary non-force push. Force, mirror, deletion, tags, multiple
refspecs, and unsupported transports fail closed until explicitly designed.

## Frozen expansion

Until the broker-enforced path above is usable end to end, the following are
maintenance-only: new generic agent frameworks, more policy categories, DLP
detectors, TPM/remote attestation, OTLP, additional sandbox backends, and broad
multi-agent governance. Security fixes and dependency maintenance remain in
scope; new horizontal features do not.

## Known debt

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
