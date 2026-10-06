# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The `[Unreleased]` heading is rolled forward manually before each release; do not delete it.

## [Unreleased]

### Security

- Bounded follow-up review and red/green evidence:
  [2026-10-06 report](docs/security-review-2026-10-06.md). This is unreleased
  work; the immutable `v0.2.7` tag does not contain these fixes.
- Restricted Shell validation refuses raw control bytes outside literal data,
  including nested executable regions, rather than trusting grammar-only
  whitespace/comment boundaries. Unsupported `=name` command words are refused;
  assignment-looking literal executable words are no longer discarded from
  AST-resolved argv. Permanent parser, real SDK and hook regressions retain
  ordinary assignment, quoting and wrapper positive controls. This is bounded
  defense in depth, not arbitrary-program containment.

### Changed

- Document the accepted broker-first scope, actual Shell/execution dialects,
  optional unsigned CLI receipts, and independent parity/OS verification limits.
  The existing `v0.2.7` tag is unchanged; this follow-up is not in that tag and
  no repair version is advertised as published.

### Added

- Six localhost-only authenticated Git/TLS composition tests and a required
  native Linux CI job using the newly built broker CLI. These are not a proof
  of container isolation or completion of the planned I1–I8 deployment checks.
- Three fixture-bind checks preserve loopback defaults and restrict the
  native container fixture to the observed private Docker bridge address.
- Fixed Linux Docker reference, required native authenticated-container CI
  acceptance driver, and five actual broker execution-authorization tests.
  Native acceptance passed for the fixed synthetic Linux profile at `5f8e714`
  (CI run `37524417236`, 21/21 success); metadata
  checks, host tests and automated PTY input are not human identity proof.
- Reproducible bounded synthetic snapshot-cost driver and operational fault
  guide. Whole-CLI 1/8/32 MiB observations are not pure-copy timings, true disk
  peaks or representative production/user acceptance. An optional Unix test-only
  probe separately measures the existing copy functions and retained logical
  bytes without adding production instrumentation or a public API.

## [0.2.7] - 2026-10-05

### Security
Second-pass review; details and limits in the
[review](docs/security-review-2026-10-05.md) (F23–F44).

- Shell wrappers (`env`, `sudo`, `nice`, `timeout`, `xargs`, …): an option the
  wrapper table does not name now makes the invocation opaque instead of being
  skipped as a flag, which had let an abbreviated or unlisted value-taking
  option hand its value to the gates as the command. Attached unknown options
  also fail closed. `flock -c`, `coproc`,
  `busybox`, `caffeinate` and four more launchers are handled.
- A command word the shell computes is refused or resolved: backslash-newline
  inside a word (including repeated continuations), a pathname pattern or
  brace expansion as the command, `hash -p`,
  `alias NAME=VALUE`, `enable -f`, `trap ACTION`, and `sh -h`/`-V`.
- Git recognition: `--attr-source`/`--shallow-file` values no longer hide a
  push; `agent-guard push` is itself an outbound push. Read-only Git
  subcommands refuse `--output`, `grep -O`, `ls-remote --upload-pack`,
  `--ext-diff`, `--textconv` and `--filters`, including one-letter prefixes and
  paired negations that re-enable helpers. Harmless complete options such as
  `diff --text` and `rev-list --filter` remain subcommand-specific exceptions.
- HTTP: a request needs an absolute `http`/`https` URL; rules also match its
  canonical spellings (case, numeric and IPv6-embedded IPv4, userinfo,
  percent-encoded letters); a `Host` header must name the URL's host; read-only
  allows only `GET`/`HEAD`/`OPTIONS`. The outbound preset covers `127.0.0.0/8`,
  `[::1]` and `169.254.0.0/16`.
- Denied path rules: a wildcard inside a file name matches (`.env*`,
  `/var/log/app-*.log`); `deny_paths` ignore case on macOS and Windows and are
  matched against the requested name as well as the resolved file.
  Permission-granting `allow_paths` and `workspace_escape_paths` retain their
  pre-0.2.7 interpretation; this denial fix does not silently authorize sibling
  names such as `src-old` or waive bounds for `external-sibling`.
- Broker helpers must be scoped to canonical HTTPS destinations, like headers.
  Nonempty global helpers, wildcard/ambiguous scopes and disabled
  `credential.useHttpPath` are refused. HTTPS destinations outside all trusted
  helper/header scopes fail before preview network access; empty resets and
  anonymous configurations remain supported. This does not audit trusted
  helper programs or other transport authentication mechanisms.
- Workspace-write confinement covers `unzip -d`, `rsync`/`scp`, `curl -o`,
  `wget -O/-P`, `sort -o`, `git worktree add`/`clone`/`init`/`--output` and
  `find -delete`/`-fprint`. Attached short-option values cannot swallow a copy
  destination as another flag operand.
- A policy whose signature fails no longer supplies the audit destination or
  decides the input-content check; a failed reload is recorded as a failure.
- Approval prompts, `agent-guard list`/`show`, the hook reason and Git error
  text escape control, invisible and bidirectional characters. The broker
  accepts only an object id as a remote tip.
- Commands using the shared runner get null standard input. The macOS Seatbelt
  profile grants workspace writes only in a mode that permits them
  (here-documents therefore do not run in read-only mode on macOS). WriteFile
  refuses a FIFO or device instead of waiting on it.
- `tools.custom` rejects a repeated key and a key no custom tool id can equal.
- Plugin installer writes the audit path as a JSON string; a Windows path no
  longer produces a policy the hook cannot parse and therefore approves under.

- Broker CLI confirmation now reloads the policy and refuses changed or unreadable
  policy files before issuing a push grant. Pending SDK approvals recheck the
  current subject's Deny Fuse and rate limit without counting the request twice.
- Restricted shell validation rejects ambiguous ANSI-C NUL/non-ASCII escape
  decoding and models `sed` in-place destinations, including attached backup
  suffixes and expressions appearing after filenames. Secondary sed I/O,
  execution, external scripts, and unmodeled syntax fail closed. **Correction:**
  the sed destination fix claimed in GHSA-j64p-f672-v3jq is incomplete in 0.2.6;
  0.2.7 closes the reproduced cases. Registry availability must be verified
  before this version is advertised as the remedy in the public advisory.
- `CustomToolId` deserialization now enforces the same validation as construction.
  Anomaly window configuration cannot panic monotonic clock arithmetic.
- Unix output capture can be cancelled at its deadline even when another writer
  holds an output pipe open. This does not add cgroup-level process containment.
- Cooperating approval/audit JSONL writers lock complete frames, and approval
  readers take a shared lock. This prevents concurrent framing corruption, not
  malicious same-permission edits or crash/disk-full recovery guarantees.
- Python wrappers report awaitables only after completion; synchronous handoff
  workers report their actual outcome even if their asyncio waiter is cancelled.
  Blocking native Guard calls release the GIL so other Python tasks can progress.
- Attenu verification preserves a constraint's type and field/scope selector,
  and rejects malformed signed observation objects. The latter uses the local
  `envelope_invalid_observation` reason outside the pinned upstream vocabulary;
  upstream fixture bytes remain unchanged.
- Lockfile-only updates move `anyhow` to 1.0.103 and `event-listener` to 5.4.2,
  addressing RustSec's reported unsoundness warnings in the resolved dependency
  graph. No unrelated dependency versions were advanced.
- Node LangChain `ToolCall` envelopes are checked against their actual `args`,
  before the framework's single-use transition ticket skips nested entry points.
  Bare and enveloped forms now receive the same policy decision.
- Plugin setup aborts before modifying policy/settings when exact-version binary
  installation fails; it cannot fall back to an unverified stale PATH binary.
  The explicit `--skip-binary` opt-out and no-write `--dry-run` remain available.
- Git outbound recognition models abbreviated destructive flags, pruning,
  command-line config and aliases without losing inherited config or weakening
  decisions through unmodeled shell-argument forwarding. Quoted declarations
  and opaque environment-provided Git config cannot silently hide an update.
- Restricted-mode path checks refuse brace expansion and dot-glob components
  that can become a parent directory. Read-only commands reject program-valued
  environment, opaque ripgrep config and executable ripgrep options, while
  interpreting option values and `--` before search operands.
- Broker remote lookup selects the exact branch ref. Approval URLs must be
  printable ASCII; credential headers require an explicit URL scope and
  broker HTTP redirects are disabled. Grants use strict raw IDs, private
  permissions and atomic writes.

### Changed
- Restricted-mode sed support is deliberately bounded: ordinary inline
  substitutions and common in-place forms are supported, but external script
  files and unmodeled scripts/options now require a trusted alternative. ANSI-C
  byte/Unicode escapes outside ASCII are refused rather than guessed across
  shell locales. See the [defensive review](docs/security-review-2026-10-04.md)
  for test evidence, compatibility costs, and remaining platform limitations.
- Broker URLs containing non-ASCII text, unscoped `http.extraHeader` settings
  and nonempty global `credential.helper` entries
  now fail closed. Use an ASCII URL and a header scoped to its HTTPS destination.
  Scope helpers to a canonical HTTPS host/repository path and keep
  `useHttpPath = true`; empty helper resets remain valid. HTTP endpoints
  requiring redirection need their final URL configured directly.
  Dynamic shell aliases whose forwarding cannot be modeled require a direct
  controlled Git command or another trusted host execution path. Read-only
  ripgrep accepts modeled search options; unknown options fail closed.
- Release preparation now documents the atomic multi-language version tool and
  the requirement to tag the exact tested main merge commit. Negative version
  tests use the fixture's actual version, so later releases cannot silently
  disable their missing-pin and rollback controls.

## [0.2.6] - 2026-10-03

### Changed
- **A refused `ln` now names the link source, instead of calling it a write
  target.** `ln -s /etc/passwd workspace_link` is refused because the link
  binds a name inside the workspace to a path outside it, and a later write
  through that name lands outside — the first half of the 2026-05-14
  path-traversal escape, and the reason this arm exists. The refusal reported
  the source as a `write target`, which reads as a misparse of the command:
  `ln -s` does not write its first operand. That is a costly thing for a
  refusal to imply, because a reader who concludes the check misparsed their
  command goes looking for a way around it rather than at what it refused —
  which is what the author of this change did, ten minutes after installing
  the build.

  Verdicts are unchanged and all four `ln`/`link` regressions still pass. The
  link name stays a write target when it is the operand outside the workspace;
  only the source is reported as a source. The text keeps the substring the
  SDK maps onto `PATH_OUTSIDE_WORKSPACE`, so the decision code does not move
  with the wording, and it now states the consequence and points at
  `workspace_escape_paths` for a location that is meant to be reachable. The
  relative `../` refusal deliberately carries no such hint: the escape list
  does not rescue that case.

### Security
- **Release publication is now tied to the tested protected-main commit.** All
  third-party workflow actions are pinned to reviewed full commit SHAs,
  workflow permissions default to `contents: read`, and Dependabot tracks
  action updates. A tag-triggered release fetches `origin/main`, requires its
  checked-out commit and `GITHUB_SHA` to be identical, and queries the exact
  successful `ci.yml` push run for that SHA before any registry job can start.
  The release preflight reruns `cargo deny`, `cargo audit`, and the production
  npm dependency audit; the Rust registry job now names a dedicated
  `crates-io` environment alongside the existing PyPI/npm environments.
- **The marketplace hook now refuses silent plugin/binary version drift.** The
  wrapper parses `.claude-plugin/plugin.json`, requires the discovered
  `guard-hook --version` output to match exactly, and otherwise emits the
  documented fail-open `allow` plus a warning without running `check`. Missing
  or malformed metadata and a failed version probe follow the same path.
  Plugin metadata no longer claims that this decision-only hook produces
  signed audit receipts; its JSONL records are unsigned, while signed receipts
  require separately configured Guard-owned execution and a signing key.
- **Release version checks now distinguish source state from published
  state.** The gate covers both Python project files, both Node lockfile version
  fields, Cargo.lock workspace packages, every exact local dependency pin,
  plugin/package metadata, install examples, and current source markers. The
  atomic bump tool advances only source markers and leaves release links and
  published-package install commands unchanged until a release actually
  exists; mutation tests lock both groups independently.
- **A failed weekly deep-audit reviewer can no longer be reported as a
  successful run.** Reviewer subprocess status is preserved after report
  capture, the table marks that reviewer `fail`, remaining reviewers still
  run, and the workflow exits non-zero. A fake reviewer regression covers both
  the failure and success paths.
- **Python and Node adapters now preserve one decision snapshot and one
  complete host-handoff lifecycle.** Binding `check` and `decide` responses
  take the decision, policy version, and verification status from the same
  immutable SDK evaluation, so a concurrent reload cannot splice metadata from
  a newer policy onto an older verdict. Node `auto` now matches Python: the
  exact `bash` tool uses owned execution, while non-shell custom tool IDs use
  `run`, execute the host handler only on `Handoff`, and submit one terminal
  report. Shell-like custom IDs such as `shell`, `sh`, `terminal`, `cmd`, and
  `powershell` fail closed in `auto` until the host maps a real Bash-backed tool
  to exact `bash` or selects an explicit mode; they cannot silently widen into
  unsandboxed host execution. LangChain nested entry points use bounded,
  single-use transition tickets, so framework delegation is counted once but
  reentrant or delayed tool calls start a fresh lifecycle. Direct binding
  reports reject unknown and duplicate IDs, including when audit output is
  disabled. A successful host action whose report fails now raises
  `AgentGuardExecutionError` carrying the completed result and an explicit
  do-not-retry marker; when both action and report fail, the original
  host error remains primary with the reporting error attached. Shared parity
  fixtures lock omitted trust to `Untrusted` and invalid signatures to
  `PolicyVerificationFailed` across Rust, Python, and Node.
- **`guard-verify` no longer reports success on Attenu ledger content it only
  partly understood.** The verifier now enforces the published 39-field ledger
  vocabulary, rejects the twelve schema-v2 fields on v1 chains, validates v2
  root/allow/deny/kill/outcome records, and checks duplicate IDs across both
  allow and deny records before execution binding. Missing versions and chain
  identifiers fail closed; malformed authority scopes, constraints, TTLs, or
  unknown nested authority members are reported as unreadable rather than
  projected into a weaker grant. Re-sealed mutation tests cover every record
  family, so integrity-valid hostile shapes cannot pass as understood.
- **Compliance reports no longer call a merely present host signature
  “attested.”** Without a trusted public key, a structurally valid matching
  envelope is now counted as `signature_present_unverified`; malformed or
  outcome-mismatched envelopes are counted separately as invalid, and records
  without one are unsigned. The old `executions_reported_attested` JSON field
  is removed because it asserted verification the command never performed.
- **Runtime decisions and audit outcomes now share one immutable policy
  snapshot and request ID.** `Guard::run` no longer calls the decision path and
  then re-evaluates through `execute`; one evaluation supplies the decision,
  policy verification metadata, execution, and complete audit lifecycle.
  `DecisionEvaluation` exposes that race-free decision surface to language
  adapters. Tool decisions, execution starts, finishes or sandbox failures,
  content findings, policy reloads, anomaly records, and reported handoff
  outcomes now pass through one local-file/stdout plus SIEM fan-out; anomaly
  records carry the request ID of their matching tool decision. Handoffs
  emit an `execution_started` record before leaving the Guard boundary, so a
  later `execution_reported` record can be correlated to the original
  decision without inventing a witnessed finish. Pending handoff IDs are now
  bounded, expiring, and one-shot; their terminal record retains the original
  snapshot, audit destinations, tool, and agent across policy reloads instead
  of accepting arbitrary/duplicate IDs or relabeling every tool as `handoff`.
- **Guard-owned shell execution now has a finite resource lifecycle.** Bash
  execution defaults to a five-minute timeout (tightenable through
  `Guard::set_execution_timeout_ms`), and every built-in process runner retains
  at most 4 MiB independently for stdout and stderr before returning the typed
  `OutputLimitExceeded` error. Unix backends launch a fresh session and kill
  the process group on timeout, overflow, or root-shell exit. They also mark
  every inherited descriptor above stderr close-on-exec, preventing a
  pre-opened writable file from bypassing path-oriented sandbox rules. Windows
  uses the existing Job Object to terminate the full job before joining output
  readers. Regressions prove simultaneous pipe draining, descriptor hygiene,
  and that a background grandchild cannot write its delayed sentinel after
  timeout.
- **Linux Landlock now proves and enforces the write boundary it advertises.**
  The backend requires Landlock ABI v3 as a hard minimum, so `truncate(2)`,
  `open(2)` with `O_TRUNC`, and `ftruncate(2)` on descriptors opened after
  restriction cannot bypass read-only or workspace-only modes. Because
  Landlock cannot retroactively narrow a descriptor opened before restriction,
  the shared Unix runner closes inherited non-stdio descriptors at exec.
  Filesystem write rights now follow the effective `PolicyMode` instead of
  being granted beneath the workspace in every mode. Availability runs the
  complete restriction path in a disposable child, catching hosts that can
  create a ruleset but block
  `landlock_restrict_self(2)`; partial or older enforcement fails closed. A
  Linux CI lane exercises the exact mutation syscalls against the combined
  runner and OS boundary.
- **Approval expiry and anomaly state now preserve their stated boundaries.**
  The ledger rejects human decisions at or after the recorded expiry, and the
  resume path independently rejects a forged or legacy late approval before
  execution. Anomaly thresholds are validated against retained evidence,
  `max_calls: 1000` can now observe and reject call 1001, and capacity churn
  evicts only unlocked subjects; a durable lock cannot be erased by flooding
  4,097 fresh identities. Deployments must still supply a stable,
  host-authenticated subject identity for per-agent lockout claims.
- **Guard-owned `WriteFile` now opens workspace targets relative to a directory
  capability.** Workspace-scoped execution no longer validates an ambient path
  and then reopens that path by name. Absolute/parent escapes and symlink or
  ancestor swaps are refused during the capability-relative open itself;
  deterministic race regressions prove that neither an existing link nor a
  link installed between validation and open can redirect bytes outside the
  workspace. Explicit `FullAccess` retains its documented ambient write
  authority.
- **Restricted shell validation now fails closed on unresolved destinations and
  unknown read-only executables.** Dynamic or home-relative targets (`$VAR`,
  `${VAR}`, and `~`), existing symlink components that resolve outside the
  workspace, `truncate` destinations, archive extraction directories, and BSD
  `xargs -J` command operands can no longer fall through as safe. Read-only
  mode now uses a finite executable/Git-subcommand allowlist instead of
  treating an unrecognized program as proof of read-only behavior. These are
  intent-gate improvements; hostile arbitrary programs still require an active
  OS sandbox for containment.
- **The unsafe Windows AppContainer prototype is disabled.** It replaced the
  workspace DACL without restoring the original descriptor and double-owned
  inherited pipe handles, so success or failure could mutate host permissions
  or close a handle twice. The compatibility feature now reports unavailable
  and refuses direct execution; by-name selection resolves truthfully to
  `none`, while default selection may use the independently probed Low-IL Job
  Object backend. Re-enabling AppContainer requires Windows tests proving exact
  DACL preservation and single handle ownership on every exit path.
- **Guard-owned HTTP execution now ignores inherited proxies, bounds response
  bodies, and fails closed on extension methods.** The pinned client disables
  `HTTP(S)_PROXY`/`ALL_PROXY`, so an environment proxy cannot receive a request
  in place of the vetted destination. Only `GET`, `HEAD` and `OPTIONS` may take
  the documented host-handoff path; WebDAV, custom and unsafe verbs enter the
  owned path and are rejected before DNS unless explicitly implemented. HTTP
  responses are capped at 4 MiB, and the synchronous executor no longer
  creates one extra unbounded OS thread per call. A global 64-request
  in-flight budget now fails fast before DNS or socket work when the guarded
  executor is saturated.
- **Linux seccomp no longer drops an unresolved required deny rule.** The
  complete network, dangerous-syscall and mode-specific write rule set is
  preflighted before filter installation; any resolution or installation
  failure returns `FilterSetup`. `SeccompSandbox::new()` and `strict()` are now
  both fail-closed, and a build without native seccomp support cannot execute
  an unfiltered compatibility shell while reporting `linux-seccomp`. The
  capability doctor now runs an unsandboxed control write in a private probe
  directory and requires the equivalent read-only sandbox write to fail, so a
  green health result proves a representative deny instead of only proving
  that `echo` can run.
- **A one-use push grant is now claimed before any repository inspection or
  network-capable Git command.** Grant schema v2 retains the exact approved
  transaction. Execution atomically burns the grant, validates its policy,
  expiry and self-digest, then compares the repository's current push URL and
  local OID using local-only operations. Only the URL stored in the grant may
  reach `ls-remote` or `push`. Changing `pushurl` after approval is therefore a
  refusal with a retained grant ID and transaction, and the changed endpoint
  receives no connection; legacy v1 grants are readable but refused by the
  broker executor because they do not carry enough evidence for this check.
- **Policy typos and condition errors now fail closed.** Fixed-schema policy
  objects reject unknown fields, empty selectors and invalid HTTP method
  tokens during loading; valid extension methods remain available to explicit
  rules. Invalid condition operand types are rejected when possible at load
  time, and any residual runtime evaluation error produces an
  `INTERNAL_ERROR` deny instead of silently making a deny/ask rule not match.
  Invalid anomaly thresholds and audit destinations are rejected as well.
- **An invalid signed policy now blocks every public decision entry point.**
  `check`, `check_tool`, `decide`, `decide_tool`, `execute` and `run` all share
  the same `POLICY_VERIFICATION_FAILED` chokepoint; callers can no longer use a
  decision-only API to obtain `allow`/`execute` from a policy whose detached
  signature failed verification.
- **The Node framework adapter now defaults omitted trust to `Untrusted`.**
  This matches the Rust and Python contract. Hosts that deliberately want the
  broader trusted policy path must pass `Trusted` explicitly.
- **`DecisionReason` no longer derives `Deserialize`, closing a
  blank-approval-prompt path.** Its fields are `pub(crate)` and construction
  funnels through `new`, which substitutes a placeholder for an empty message —
  but a derived `Deserialize` populated those fields regardless of visibility,
  so any downstream crate could synthesize a reason with an empty `message` from
  JSON and wrap it in `AskUser`. `GuardDecision` and `RuntimeDecision` already
  omit `Deserialize` for the same reason. Their approval variants are now
  individually `non_exhaustive`, so downstream crates must use the validated
  constructors and cannot supply a blank prompt with a struct literal; all
  constructors also replace whitespace-only prompts/reasons. This is a source
  compatibility change for downstream code that deserialized `DecisionReason`,
  directly constructed approval variants, or destructured every variant field;
  audit readers should deserialize the stable audit/receipt wire types instead.
  A `compile_fail` doctest locks the deserialization boundary. Type-design audit
  finding.
- **A path waived past the workspace bound by `workspace_escape_paths` stayed
  waived wherever it led.** The globs are matched against the path as written,
  and a match dropped the bound for that call entirely, so a symlink inside an
  escape-listed root carried the exemption out of that root. With the escape
  list this project dogfoods (`/tmp/**`, `**/.claude/projects/**`), an agent
  able to create a link under `/tmp` could write through it anywhere the tool
  policy did not separately deny — `deny_paths` still covered `/etc`, `~/.ssh`
  and the rest of that list, and nothing else. The symlink containment added on
  2026-05-15 held on every path except the ones a policy had opted out of the
  bound for, which are exactly the paths a policy author reads as "somewhere
  else I trust", not "anywhere at all".

  An escape entry now waives the bound for the location it names, not for
  whatever a path under it points at. The globs are re-checked against the
  resolved path, and a path that no longer matches is held to the workspace
  bound like any other. A link that stays inside the escape-listed root — the
  case the list exists for — is unaffected.

  Scope, stated plainly: this is the advisory hook's file-write boundary, which
  `CLAUDE.md` already describes as decision-only and fail-open rather than
  hostile-agent containment. Bash targets are governed by the validator's own
  lexical copy of the escape list; that layer canonicalizes nothing, so it made
  no symlink guarantee before this change and makes none after it.

### Changed
- **`guard-verify` reads schema-v1 attenu chains instead of rejecting them
  outright.** Every bundle in `bundle_vectors_v1.4` is a `schema_version=2`
  chain, so no published row exercised a v1 ledger, and this verifier failed
  any v1 bundle wholesale under a reason of its own. attenu-guard has accepted
  a v1-chain row for the next corpus revision (a2aproject/A2A#1575), so the v1
  rules are pinned now, from the corpus README alone, before that row exists:

  - version consistency uses the README's tokens: `unsupported_version` (was
    `unsupported_schema_version`, a name no row had ever checked),
    `anchor_version_mismatch`, `root_version_mismatch` and
    `mixed_entry_versions`, the last reported once, at the first entry that
    disagrees — the root included, since the README exempts no entry;
  - an undefined `policy` value is `invalid_policy` on a v1 chain and stays
    `invalid_allow`, the v2 record check's name, on a v2 chain. The rule is
    version-independent, and on neither does the value buy a containment
    exemption;
  - execution binding runs on v2 chains only. `attenu-bundle` output gains
    `execution_binding`, which is `"not applicable"` on a v1 chain rather than
    leaving an empty failure list to imply the pairs were found sound.

  The upstream README now publishes the exact v2-only field set, so derived v1
  cases remove those twelve fields before re-sealing. A separate negative
  mutation adds one back and pins `v2_field_on_v1`.
  `unsupported_canonicalization` remains outside the contract: the README has
  no token for a non-JCS `c14n`.

### Fixed
- **The 20 of 20 `guard-verify` reported for `bundle_vectors_v1.4` never read
  the counters one row pins.** The corpus README defines `expect_report` as
  counters "a conformant implementation MUST reproduce exactly".
  `valid_bundle_v2_ungated_allow` pins `actions_checked: 2, ungated: 1`, which
  is the only thing separating a verifier that reports an un-gated allow from
  one that silently skips it: both accept. The scorer deserialized past the
  key, and the report had no such counters. The report now carries both under
  the corpus's names. The scorer checks every pinned counter, and a counter
  this verifier does not report fails the case instead of passing it. The
  score is still 20 of 20, now with that row's counters in it; the envelope
  corpus stays 19 of 19.

  A pass over the README's reason table found three more places where this
  verifier used a name of its own, or none:

  - an outcome on a different node than its allow was `outcome_node_mismatch`;
    the table's token is `cross_ref`;
  - an allow by a node the bundle never spawned was `unreadable_authority`,
    which the table puts on a root only; it is `containment`. A spawn from a
    parent never established is now `monotonicity`, since a parent holding
    nothing cannot contain a grant. That one is this verifier's reading: the
    table names no reason for the shape;
  - `missing_root` (zero or several roots) and `chain_id_mismatch` (an entry
    or the anchor naming another chain) were never emitted.

  `attenu-vectors` also prints the corpus revision it scored, which the README
  says is what a report should name. `expected_head_mismatch` and
  `expected_anchor_mismatch` remain outside this command because they need an
  independently retained head that the verifier is not given. The v2 record
  schema gaps named in this original review are closed by the security entry
  above.

## [0.2.5] - 2026-09-14

### Security
- Updated the locked `rustls` dependency from 0.23.40 to 0.23.45 to address
  RUSTSEC-2026-0285, which allowed selected TLS 1.3 handshake messages to be
  accepted at the wrong encryption level.

### Changed
- **The push preview leads with what you must not skim past, and a shape the
  broker will not perform is declined before you are asked.**

  Every preview rendered as the same block with different values in it, so a
  routine fast-forward and a push that discards remote history were the same
  shape to a skimming eye. Anthropic's telemetry puts approval at roughly 93%
  of prompts, and a study where the malicious command was printed directly
  above the prompt still had two thirds of readers approve it — so more text is
  not the fix. What pharmacy did for look-alike drug names was make the
  *difference* salient rather than the label longer, and that is what this is:
  a non-fast-forward or an undetermined update now states its consequence
  above the details instead of inside a line of equal weight.

  Deliberately not fired on: commit count. Without knowing what the reader
  expected, a large number is not a surprise, and a marker that fires on volume
  is one people learn to dismiss.

  Separately, `run_push` now declines a shape `execute_push` will not perform,
  before asking and before issuing a grant. It used to ask, spend a one-use
  grant, and then refuse at execution — so a human paid attention and an
  approval for a refusal that was knowable before either. `RefUpdateKind::is_executable`
  is the one place that set is written; `execute_push` reads it too, because
  two copies drift silently and the drift is an offer the execution then
  refuses.

  **A read-back confirmation was written and removed.** Requiring the branch
  name typed back is the surgical time-out, and it was the other half of this
  change until running it showed there is nothing to gate: every shape that
  raises a consequence is one the broker refuses anyway, so it only asked a
  human to type in front of a wall. Worth revisiting if the executable set
  grows to include a shape worth pausing over; shipping it now would have been
  friction sold as safety.

  `preview.rs` is a new module. The ordinary path is byte-for-byte unchanged:
  a fast-forward still prints what it printed and still costs one keystroke.

## [0.2.4] - 2026-09-09

### Security
- **The push broker no longer lets an agent-controlled repository choose what
  the credential-bearing Git process executes or where it pushes.** Versions
  0.2.2 and 0.2.3 previewed `remote.<name>.url` but executed `git push` with the
  remote name. A configured `pushurl` could therefore send the approved object
  to a different destination while the receipt named the fetch URL. The same
  process loaded repository `pre-push` hooks and execution-bearing Git config.

  The broker now resolves exactly one repository-local push URL and uses that
  literal URL for both `ls-remote` and `push`. Remote contact and execution run
  from a broker-owned temporary bare snapshot containing regular refs and
  primary objects but no repository config, hooks, alternates or replace refs.
  HTTPS and SSH are allowed by default; other transports fail closed and local
  files require an explicit test/demo opt-in.

- **The broker reads credential and transport configuration only from a
  dedicated host-owned file.** `agent-guard push --git-config <path>`,
  `AGENT_GUARD_BROKER_GIT_CONFIG`, and
  `~/.agent-guard/broker.gitconfig` form the lookup order. The file is copied
  before use and limited to `credential.*`, `http.*`, and `ssh.variant`.
  Repository paths, symlinks, group/world-writable files, includes, URL
  rewrites and execution-bearing keys are refused.

- **The hook no longer turns an unusual remote or branch into an injectable
  remediation command.** Copyable broker hints are emitted only for the
  broker's restricted plain-name grammar; whitespace, shell metacharacters,
  quotes, substitutions, backslashes, newlines and option-like names receive
  prose guidance with no runnable command.

### Fixed
- The transaction used for grant spending is now the same object used by Git
  and sealed into the receipt. A grant consumed before a later refusal remains
  named in that receipt, and expected negative Git statuses are distinguished
  from fatal transport failures.
- The npm plugin verifies the exact version of both installed binaries. A
  stale or unrelated PATH binary is not reused; the matching cargo-installed
  binary is force-installed and verified before being wired into the hook.
- **The bundle corpus moves to `bundle_vectors_v1.4`, and this verifier scored
  17 of 20 against it before knowing the field existed.** Two rows added at
  v1.4 pin the `policy` field, and one added at v1.3 pins the accepting case
  none of it was implemented against here.

  `policy` marks an allow the adapter let through without an authorization
  check. Its scope is a label rather than a claim of held authority, so a
  verifier must not test it for containment — running an honest un-gated allow
  through containment rejects a bundle for something the entry never asserted.
  That much this build got wrong by rejecting the accepting row.

  The other half is where the corpus is sharper than the obvious reading:
  **the exemption is earned by the one value the format defines, not by the
  field being present.** Keying on presence lets a marker anyone can write
  excuse an out-of-authority action. And `policy` is allow-only, so a `spawn`
  carrying even a defined value is invalid at the spawn.

  The check runs on every bundle rather than inside the execution-binding
  pass. Binding is checked on `schema_version=2` chains only, so a `policy`
  check living there never runs on a v1 chain and every undefined value buys
  the exemption it should not have — which the corpus README names as the
  mistake reference implementations have made.

  One change, after which 20 of 20. attenu-guard reports that its own
  unreleased branch and its TypeScript verifier had the same hole, caught in
  pre-release review; nothing released carried it.


### Changed
- **The broker CLI now applies its safe target grammar to execution, not only
  to hook hints.** Remote and branch names must begin with an ASCII letter or
  digit and then use only ASCII letters, digits, `.`, `_`, `/`, or `-`.
  Names that Git itself accepts, including `_wip`, non-ASCII names, and names
  containing `+`, are therefore refused by `agent-guard push`. Create or
  rename a safe remote alias or branch to use the broker; a plain Git push is
  outside this broker boundary.

- **The anomaly histories are `VecDeque`, so dropping the oldest entry is
  constant rather than a thousand moves.** `cap_history` dropped the front of a
  `Vec`, which shifts every remaining element. At `HISTORY_CAP` that is a
  thousand moves on **every tool call**, on the hottest path in the SDK.
  `pop_front` is O(1).

  `ActorState::call_history` and `denial_history` change type. They are `pub`
  in a `pub mod`, so this is a public change; nothing in this workspace or in
  either binding reads them.

- **The two corpus commands stopped being one function written twice.**
  Reading and parsing a corpus, printing the permitted extras, and the tally
  with its exit code were duplicated between the bundle and envelope runs.

  Only the parts that pay were extracted. A first attempt also factored out the
  per-case printing behind a five-parameter helper, which made the file **seven
  lines longer** than the duplication it removed — two nine-line call sites for
  one saved loop. That part was put back inline and only the three clear wins
  kept, for a net seven lines fewer and no duplication left.

  `guard-verify/src/main.rs` remains over the 800-line guidance either way;
  getting it under means moving commands into modules, which this is not.


### Changed
- **The envelope corpus moves to `envelope_vectors_v1.2`, and the verifier
  scores 19 of 19 unmodified.** Row 19,
  `reject_duplicate_subject_defective_second`, exists because this verifier's
  author reported that row 17 could not separate two orderings: with both
  envelopes valid, claiming an entry before judging the envelope and judging
  before claiming reach the same answer. The new row makes the second envelope
  also malformed, where they diverge — claim-first reports the duplicate and
  the entry falls back to `process-asserted`, judge-first reports only the
  signature and leaves the entry `witness-signed`, a state nobody witnessed.

  attenu-guard confirmed the row separates by moving that block after the
  signature check in a copy of its own verifier and watching row 19 fail while
  row 17 still passed. It ships in attenu-guard 0.15.0 and attenu-guard-ts
  0.9.0; rows 1 to 18 are byte-identical to `v1.1`.

  Passing it required no change here, which is the expected result and not
  evidence of much: the row was written from this implementation's own
  description of the gap. What it does establish is that the description was
  executable — someone else built the discriminating case from it and two
  independent implementations agree on the answer.


## [0.2.3] - 2026-09-06

### Added
- **`guard-verify` scores the attenu-guard observer-envelope corpus: 18 of 18,
  first run.** An observer envelope is an Ed25519 signature over the identity
  of one committed ledger entry — the question a ledger cannot answer about
  itself, which is whether anything outside the writing process ever saw the
  event. `guard-verify attenu-envelope-vectors` runs the published corpus;
  `verify_bundle_with_envelopes` is the API.

  **The first number is 18 of 18, and that is not the verifier getting
  better.** The bundle corpus scored 9 of 17 first, with every check right and
  every reason name wrong. That result was the argument for publishing the
  envelope vectors as text *before* anyone implemented them, and attenu-guard's
  README quotes it as the reason they did. So a clean first run is the
  process working, not the implementation being sharper — and it says only
  that two implementations agree on one frozen corpus.

  Both permitted extras land where the corpus says they may: an
  `envelope_bad_signature` alongside `envelope_non_canonical` on the row whose
  bytes were re-signed, and a second `envelope_subject_mismatch` on the other
  covered hop of a rehashed chain.

  Three decisions the corpus pins that are worth naming:

  - **The entry hash is recomputed, never read.** Reading the stored `hash`
    would let the edit that moved an entry also move what the envelope is
    compared against, which is exactly the attack the envelope exists to catch.
  - **An entry is claimed the moment `subject.seq` finds it**, before the
    envelope is judged on anything else, so a second envelope over one entry
    cannot escape the one-envelope rule by also being malformed. Without that,
    array order decides the state.
  - **`witness.alg` is contract, not negotiation.** Comparing it only against
    the trust-set row accepts `"none"` the moment both sides say so; ignoring
    it hands a non-Ed25519 envelope to an Ed25519 verifier and blames the
    signature, which was never the problem.

  Written from the published format description, without reading either
  reference implementation — the same discipline as the bundle verifier, since
  agreement is evidence about the format only when the code is not shared. The
  fixture's sha256 was checked against the published hash before scoring, and
  is pinned by a test.

- **Credential isolation has a page, and a way to check it.** The README said
  twice that keeping credentials away from the agent is a deployment decision
  this code cannot enforce, and both times stopped there. A reader who wanted
  the property had a disclaimer and no instructions.

  [Credential isolation](docs/guides/operations/credential-isolation.md) states
  the requirement in one sentence — the push credential must live somewhere the
  agent's process cannot read — and is explicit that a default install
  satisfies none of it, because the agent and the broker are the same user with
  the same `~/.ssh`. It gives the deployment that does hold (the agent in a
  container, the credential on the host), the weaker same-machine measure that
  is sometimes all you can do (a hardware key requiring a touch), and says
  exactly how much less the second one buys.

  The part worth having is the check: `git push --dry-run` from the agent's
  environment authenticates without updating a ref, so it separates "cannot
  push" from "can push" unambiguously and safely. Configuration nobody has
  tested is a belief, and a security boundary held as a belief is the failure
  this project keeps trying not to ship.

### Fixed
- **The version bumper enumerates crate manifests instead of listing them.**
  `scripts/release/bump-version.sh` carried a hand-written list of
  `crates/*/Cargo.toml`, and `agent-guard-broker` — added at 0.2.2, after that
  list was written — was silently left behind on this bump. Its `=0.2.2` pin
  was unsatisfiable against a 0.2.3 workspace, and the only thing that noticed
  was cargo failing to resolve: `scripts/check-version-consistency.sh` reported
  the tree consistent, because it checks the version markers and not the
  inter-crate pins. The list is now a filesystem glob, so a crate added
  tomorrow is covered today.

- **The plugin now installs the command the hook names.** `npx agent-guard-plugin init`
  installed `guard-hook` and nothing else, while the gate it wired up printed
  `agent-guard push --remote origin --branch main` when it stopped a push. That
  command ships in `agent-guard-cli`, which was never installed and never
  mentioned — so the documented first run ended at `command not found`.

  This is the same dead end as the fix below, one step further out: that one
  made the command parse, and a human still did not have the binary. `init`
  installs both crates, reports a partial install per binary rather than as one
  success, and says what each missing binary costs.

  A test reads the hint's own source, extracts every `<name> push --remote`
  command it prints, and asserts the plugin installs `<name>`. The invariant
  spans a Rust crate and a Node installer, which is why two rounds of testing
  each side passed while the path between them was broken.

- **The command the hook tells you to run now runs.** A refused push printed
  `agent-guard push --remote origin --branch main`, and running exactly that
  died on a missing `--policy`. The hint added in 0.2.2 existed to remove a
  dead end, and it had moved the dead end one step later instead.

  `--policy` is now optional, resolving to `$AGENT_GUARD_POLICY` and then to
  the policy `npx agent-guard-plugin init` installs. That default is not an
  arbitrary guess: it is the file the hook itself is wired to, so the push is
  evaluated against the same rules that refused it rather than a different
  set. With no policy there at all, the error names the path it tried and how
  to get one, rather than printing a usage line.

  The policy in force is printed in the preview whether or not it was named on
  the command line. Approving a push means approving it under some set of
  rules, and a default that goes unstated is a rule set the person deciding
  never saw.

  A test asserts the CLI accepts the exact argument shape the hook prints.
  That invariant spans two crates, which is why nothing caught it breaking.
- **The broker crate's documentation described a crate that no longer exists.**
  `agent-guard-broker`'s crate-level docs were written when only the
  transaction resolver had landed, and still announced "No credential
  handling, no authorization, no execution, no receipt" — with `issue_grant`,
  `execute_push`, `execute_push_with_receipt` and `PushReceipt` exported ten
  lines below. Understating which properties are present is the safe direction
  to be wrong in, and it is still a false claim about a security boundary,
  sitting in the first thing a reader of the crate sees.

  The docs now describe the path the crate runs — resolve, grant, spend
  against a freshly resolved transaction, push with both ends pinned, receipt
  — and say which parts remain the caller's: policy is evaluated above this
  crate, and what the crate enforces is that the policy has not changed since
  the approval. The boundary that is still true is kept: credential isolation
  is a deployment property this code cannot verify.

## [0.2.2] - 2026-09-04

### Fixed
- **The approval prompt is a sentence again.** A push awaiting approval
  serialized its entire parsed intent into the prompt — four hundred
  characters of JSON in a permission dialog, with anything actionable arriving
  after it. The prompt now reads `Approve git push to origin, main — force:
  may discard commits on the remote`, and the structured intent stays in the
  decision's `details`, where it was already being written and where a
  consumer can parse it. Two audiences, two renderings.
- **An unverified argv candidate is no longer offered a concrete replacement.**
  A command like `wrapper git push origin main` has execution semantics the
  parser could not establish, so suggesting `agent-guard push --remote origin
  --branch main` asserted the two were equivalent — the confidence that
  detection mode exists to withhold. It now says the wrapping program's
  behaviour was not established and leaves the substitution to the human.

### Added
- **A refused push now says where to go.** The hook attached a policy code
  and nothing else, so an agent stopped at `git push` left the human with no
  route: the broker path existed and was invisible unless they read the docs.
  A refusal or prompt on a recognized push now carries the exact command —
  `agent-guard push --remote origin --branch main`.

  The hint is only as specific as it can honestly be. Force pushes, mirrors,
  remote branch removal and multi-refspec pushes say the broker does not
  perform that shape rather than pointing at a command that would refuse. A
  push naming no branch, or a `src:dst` refspec, asks for the branch instead
  of guessing which half was meant. Commands that are not a recognized push,
  and shells too complex to parse, get no hint at all — advice on an
  unrelated denial trains people to ignore advice.
- **`agent-guard push`: the broker has an entry point.** The five broker
  properties existed as a library nobody could reach. One command now runs
  them end to end: it evaluates the equivalent command against policy, prints
  the effect resolved from the repository and the remote, asks, then
  re-resolves and spends a one-use authorization against what it just
  resolved before pushing.

  Policy is evaluated, not merely pinned. A push the policy denies never
  reaches a human — asking someone to approve what policy already refused
  teaches them to click through refusals.

  When no signing key is configured the command says the receipt is unsigned
  and that nobody else can check it, rather than printing an official-looking
  record.

  `agent-guard-broker` is published from this release: the condition its
  manifest recorded for that — having an entry point — is now met.
- **`agent-guard-broker`: a receipt for every attempt.** `execute_push_with_receipt`
  records what the broker witnessed — the transaction it resolved, the grant
  it spent, and whether the push landed or was refused and why.

  A receipt is emitted for refusals too. The interesting thing a broker does
  is decline, and a record covering only successes cannot show that it ever
  did.

  A receipt is emitted with no signing key too, as `Witness::Unsigned` rather
  than as nothing. Absence would read as "no push was attempted", and an
  operator reaching that conclusion because a key was not configured has been
  misled by their own tooling — the same failure as anomaly records reaching
  only a sink most deployments do not configure. An unsigned receipt never
  verifies: it is a truthful record and not evidence anyone else can rely on,
  and the two must not blur.

  The signature covers the outcome, so rewriting a refusal into a success
  does not survive verification.
- **`agent-guard-broker`: broker-owned execution.** `execute_push` resolves
  the transaction afresh, spends the grant against what it just resolved, and
  pushes. Spending against a freshly resolved transaction makes authorization
  and drift detection the same check: a grant is bound to a digest, so a
  transaction that moved no longer matches it and cannot be spent. There is no
  separate drift step to forget to call.

  The push pins both ends rather than trusting a reading taken moments before.
  The source is the approved object id, not the branch name, so a commit made
  after approval cannot ride along. The destination carries a lease on the
  approved remote object id, so the server refuses when the remote is no
  longer what the human was shown — a remote advanced by someone else is a
  state nobody approved, even when the update would still fast-forward.

  Only fast-forwards and branch creates execute; anything that would discard
  history is refused. The grant is spent by then, so a refusal costs a fresh
  approval, which is the intended price.

  Credential isolation remains a deployment property this code cannot verify,
  and the module says so: the push uses whatever credential the broker
  process holds, which is a boundary only if the agent has none of its own.
- **`agent-guard-broker`: one-use authorization.** A grant records a human
  decision about exactly one resolved transaction, bound to its digest, the
  policy hash in force, an actor and a deadline, and can be spent once.

  Spending is a rename into a `spent/` directory, which is one atomic
  filesystem operation: of many callers racing for the same grant, exactly one
  succeeds. Nothing reads the grant to decide whether it is still available,
  because a read followed by a write has a window between them and that window
  is the whole of what one-use has to exclude. A 16-thread test asserts exactly
  one winner.

  A presented grant is consumed whether or not it authorizes what was
  presented. The only reasons validation fails are that the effect changed or
  that someone is probing, and both need a fresh human decision anyway, so
  nothing is lost — while validating first would let one approval be tried
  against many transactions.

  The deadline is recorded in the grant rather than left in the process that
  enforces it, so someone holding a spent grant can check that a refusal for
  expiry was correct.
- **`agent-guard-broker`: the exact Git push transaction, and drift against
  it.** The first piece of the broker-enforced push path in `ROADMAP.md`.
  `resolve_push_transaction` answers, from the repository and the remote,
  what a push would actually do: the URL the remote name resolves to, both
  object ids, whether the update creates, fast-forwards, discards history or
  does nothing, and which commits the remote would gain. The remote tip is
  read from the remote itself rather than from a local tracking ref, which is
  a cache and may be arbitrarily stale.

  `drift_against` re-resolves an approved transaction immediately before a
  push and names every difference — remote repointed, local moved, remote
  moved, kind changed, commits changed — because those call for different
  actions from a human.

  A remote holding objects this repository has never fetched is reported as
  `Undetermined` with no commit list, not as `NotFastForward` with an empty
  one. The relationship cannot be established without fetching, and saying
  "history would be discarded" when the truth is "this cannot be determined"
  tells a human something was established that was not.

  Not published, and deliberately incomplete: no credentials, no
  authorization, no execution, no receipt. Nothing here can push.

### Fixed
- **The attenu bundle verifier reports the corpus's containment reasons.**
  Scoring against `bundle_vectors_v1.2`, which added the nine delegation
  containment rows this path previously had no negative coverage for, gave
  9/17. Every one of the eight failures was the same shape: the violation was
  detected and positioned correctly, but reported as `not_narrower` or
  `scope_not_authorized` — names invented here while no corpus row exercised
  the rules — where the corpus requires `monotonicity` and `containment`.
  Adopting the corpus vocabulary takes it to 17/17. The logic was already
  right on all four containment dimensions, including the two the reference
  implementation itself had wrong.

### Added
- **A host can now sign the outcome it reports back from a handoff.**
  `RuntimeOutcome::Handoff` gives the action to the host, which runs it
  outside the Guard. The resulting `ExecutionReported` record said where the
  claim came from and carried nothing anyone could re-check it with, so a
  reader had to take the host's word and could not tell whether anybody had
  vouched for it. `HandoffResult` accepts an optional `HostAttestation` — an
  Ed25519 signature over the request id, exit code and duration — which the
  Guard records on the audit event.

  What that establishes is bounded, and the type says so: the signature binds
  a named key to an exact claim, so a third party cannot forge it and an edit
  to the recorded outcome stops matching it. It does not make the exit code
  true. The execution happened outside the boundary and nothing signed inside
  the boundary can reach it; a host that lies produces a valid attestation of
  its lie. What changes is that the lie is attributable and cannot be quietly
  revised, and that a reader can tell an attested claim from an unattested
  one.

  The Guard refuses to attach an attestation that describes a different
  outcome than the one reported — a check that needs no key — and
  `guard-verify report` counts attested and unattested host-reported
  executions separately rather than letting the total blur them. The Python
  and Node bindings expose no host key, so outcomes reported through them are
  honestly unattested.

### Changed
- **npm publishing moves to trusted publishing (OIDC).** The npm job no
  longer carries a long-lived token: it declares `id-token: write`, runs a
  Node whose npm CLI can exchange the Actions OIDC token, and lets npm attach
  provenance by default. This replaces a granular token with bypass-2FA set,
  which expires 2026-12-01 and whose mechanism npm ends in January 2027 —
  npm's own token form recommends trusted publishing for CI. The job asserts
  its npm version, because an npm older than 11.5.1 does not refuse OIDC, it
  quietly falls back to token auth.

### Fixed
- **Anomaly and lock records reach the audit sink, not only a SIEM webhook.**
  `AgentLocked` and `AnomalyTriggered` were built in one place and handed
  straight to the SIEM exporter, which returns early when no webhook is
  configured. On a file-audited deployment — what the plugin preset sets up —
  the record naming the lock was written nowhere, while the lock itself
  appeared only as a `code` on the ordinary `tool_call` line. Any consumer
  counting those record types was structurally always zero, `guard-verify`'s
  compliance report among them. Both records now go to every configured sink,
  gated on `audit.enabled` like the tool-call line.
- **An anomaly verdict carries the observations it was derived from.** The
  rate limiter and the deny fuse decide against in-memory histories that are
  destructively pruned to the current window, and the emitted record said only
  that a limit was exceeded. `AnomalyEvent` now carries `evidence`: the rule,
  the window, the threshold, the observed count, the in-window witnesses as
  wall-clock timestamps, and a `truncated` flag set when the history cap
  dropped older entries so the count is a lower bound rather than an exact
  reconstruction. A reader holding the record can recompute the verdict
  instead of taking it on faith.

  Decisions still compare monotonic `Instant`s, so a system clock stepping
  backwards cannot age observations out of a window; the wall-clock witnesses
  exist only to make the verdict checkable outside the process. The two clocks
  are recorded together and neither is derived from the other. A lock's
  evidence is captured at the moment the fuse trips and replayed unchanged
  afterwards, because a lock outlives the window that caused it.

  `AnomalyDetector::check` returns `AnomalyVerdict` (status plus evidence)
  rather than a bare `AnomalyStatus`.
- **An approval expiry now carries the bound that justified it.** The
  approval deadline existed only as a process-local `Instant` inside the
  waiting loop: not serialisable, not comparable across processes, and never
  written down. Someone holding the whole ledger could see that a request
  expired between two timestamps and could not check whether the configured
  timeout was 150 milliseconds or thirty minutes. `ApprovalRecord` and the
  `created` ledger event now carry `expires_at`, derived inside
  `create_pending` from that record's own `created_at` so the two fields are
  related by exactly the configured timeout. A terminal `Expired` with no
  recorded deadline is an unverifiable claim, and reads that way rather than
  passing silently. Ledgers written before this field parse with
  `expires_at: None`.

  `ApprovalLedger::create_pending` takes one further argument, the optional
  timeout. A request created outside a waiting caller passes `None`, because
  nothing will expire it.

## [0.2.1] - 2026-09-02

Release engineering only; no library or policy behaviour changed. `0.2.0`
reached crates.io but stalled before PyPI and npm, and finishing it needed
workflow changes, which only take effect at a new tag.

### Fixed
- **The crates.io publish retries a rate limit.** Publishing seven new crates
  in one run hits the new-crate limit: `0.2.0` published five and then took a
  `429` on the sixth, leaving `guard-hook` and `guard-verify` behind. The
  probe before the publish and the visibility poll after it already retried;
  the publish itself now does too, and still fails immediately on any other
  error.
- **The Linux arm64 wheel is built natively.** `aws-lc-sys` reaches the SDK
  through `reqwest` -> `rustls` -> `aws-lc-rs`, and its C sources do not
  survive the manylinux2014 aarch64 cross toolchain. That wheel now builds on
  an `ubuntu-24.04-arm` runner, which removes the cross step rather than
  upgrading it.
- **The retired `macos-13` runner is replaced by `macos-15-intel`.** A job
  targeting `macos-13` is never scheduled — it queues until timeout — and
  because the PyPI upload requires every wheel in the matrix, the `0.2.0` run
  could not reach PyPI or npm however often it was restarted.

## [0.2.0] - 2026-09-02

### Added
- **Structured Git push intent matching for recognized execution forms.**
  Equivalent entry points such as quoted/escaped executable names, absolute
  executable paths, explicitly modeled `env` / `command` / `stdbuf` / `setsid`
  wrappers, `git -C`,
  `--git-dir`, `git-push`, and grouped shell forms now share the canonical
  `git push` policy decision. Force/lease/mirror/delete flags and destructive
  `+source:destination` / `:destination` refspec shorthand are normalized so a
  raw-string spelling cannot downgrade a deny to an ask or allow. Locked by
  security regression `sec29` and tests against the shipped outbound preset.
- **Plumbing-level Git egress recognition.** `git send-pack` and
  `git-send-pack` now enter the same exact outbound authorization path as
  porcelain `git push`, while structured previews retain the actual command.
  Force, lease, mirror, deletion, and forced-refspec semantics share the same
  policy decision and audit record. Locked by security regression `sec31`.
- **Third-party conformance: an offline verifier for attenu-guard evidence
  bundles.** `guard-verify attenu-bundle` re-derives a schema-v2 bundle from
  its own bytes — RFC 8785 canonicalization, the SHA-256 entry chain, the
  HMAC-SHA256 anchor over a head recomputed from genesis rather than read
  from the ledger, delegation containment, and the allow-to-outcome execution
  binding. `guard-verify attenu-vectors` scores it against a published corpus
  under that corpus's minimal-set rule. Written against the published format
  description only; it does not read, port, or invoke either attenu-guard
  reference implementation, so agreement is evidence about the format rather
  than about shared code. Scores 8/8 on `bundle_vectors_v1`, vendored with its
  pinned hash under `crates/guard-verify/fixtures/attenu/`.

### Security
- **Static shell command words now share one policy identity.** Executable names
  expressed with single/double quotes, concatenated quote fragments, or
  backslash escapes are evaluated to the same policy subject as their Bash
  runtime value. Both the wrapper spelling and its unwrapped command are
  checked, closing deny-to-allow bypasses such as `"sudo"` and
  `stdbuf -o0 "git" push --force`.
- **Known process launchers are handled conservatively.** Modeled launchers are
  unwrapped, including command-mode `ionice`, `taskset`, and `chrt`; their
  existing-process modes and explicitly listed launchers with unsupported
  grammars are rejected in restricted modes. Security regression `sec30` locks
  the explicitly modeled and listed launchers. This is not an exhaustive proof
  about arbitrary program semantics.
- **Unknown argv prefixes cannot weaken a recognizable Git outbound decision.**
  Adjacent standalone `git push`, `git-push`, `git send-pack`, and
  `git-send-pack` argv candidates receive the same ask/deny strength as their
  modeled forms. These candidates are labeled `embedded_argv` with unverified
  execution semantics in previews and audit records. This deliberately
  conservative check, locked by `sec32`, is a defense-in-depth heuristic rather
  than launcher-class containment; the credential-isolated broker remains the
  class-level boundary.
- **Approval resume now revalidates before execution.** An approved ledger
  record must still match the request id, tool, payload hash, agent id, and
  timestamp ordering; the current policy and signature state are checked again
  on the same execution snapshot, and a new deny always wins. The local JSONL
  ledger remains explicitly unauthenticated and is documented as a
  single-user coordination workflow, not a hostile-agent authorization broker.

### Changed
- **Release publication is ordered and restartable.** The tag workflow runs the
  full verification gate, publishes the seven Rust crates individually in
  dependency order, then publishes PyPI and npm sequentially. The npm installer
  installs the exact matching `guard-hook` crate version instead of repository
  `main`. crates.io 429 and server errors are retried during both the initial
  existence check and post-publication visibility polling.
- **Recoverable remote branch deletion now requires approval.** The outbound
  preset treats `git push --delete` and deletion refspecs as `ask`, while force
  and mirror operations remain denied.
- **Product scope is narrowed to broker-enforced Git push.** Documentation now
  distinguishes the fail-open advisory hook, Guard-owned execution, and the
  planned credential-isolated broker; horizontal framework, DLP, sandbox,
  attestation, and telemetry expansion is frozen until that path is complete.
- **The PyPI distribution is now `agent-guard-python`, not `agent-guard-runtime`.**
  PyPI compares project names with separators collapsed, and
  `agent-guard-runtime` collapses to the same string as the unrelated
  `agentguard-runtime`, so it was refused as too similar. Publishing beside a
  near-identical name with a near-identical description would also be
  confusing on its own merits. The import name is unchanged: `agent_guard`.

### Fixed
- **Git push previews preserve repository selectors and allowed audit intent.**
  Ordered `-C` changes, `--git-dir`, and `--work-tree` are retained separately
  with resolved preview paths; `--force-if-includes` alone is no longer
  mislabeled as force, and allowed pushes retain structured intent in audit.
- **Git outbound intent is parsed once per normal decision path.** The parsed
  metadata now flows from evaluation into the audit choke point, avoiding a
  second shell syntax-tree construction for each Bash check.
- **Validator warnings no longer mask stronger policy decisions.** A warning is
  retained as a candidate decision while raw and canonical policy subjects are
  evaluated, so a preceding destructive-command warning cannot downgrade a
  later forced-push deny to an approval prompt.
- **Pre-release install and registry checks are truthful.** Documentation uses
  checkout/path installs until `0.2.0` reaches the registries; the release
  workflow identifies itself to crates.io and distinguishes 404 from
  authorization/server failures, while version checks keep the two published
  prerelease links synchronized independently of the source version.
- **Grouping constructs can no longer hide a command from the shell gates.** The bash validator split a command on `| ; && || &` and treated the first token of each segment as the command word. Shell grammar is not flat, so `{ …; }`, `( … )`, `if/then`, `while/do`, `until/do`, `for/do`, `case`, and function bodies each presented `{`, `then`, or `do` in that position, and the command underneath was never classified — in `workspace_write`, `{ touch /etc/x; }` was allowed while `touch /etc/x` was denied. Commands are now recovered from a real syntax tree (`tree-sitter-bash`, new `bash::ast` module), so nesting cannot conceal one. This closes the bug class behind roughly fifteen previous point fixes rather than adding one more instance to them. Locked by `sec27` and by a 51-case corpus (`agent-guard-validators/tests/fixtures/shell_bypass_corpus.json`) that replays every historically closed bypass.
- **The bash path gate no longer fails open when the workspace root is unverifiable.** An absent or relative `working_directory` normalised to an empty path, and `Path::starts_with` against an empty prefix is vacuously true, so every absolute write/read target counted as "inside the workspace" — the gate silently permitted host-wide writes. Absolute targets now fail closed when no absolute workspace root is configured (after the policy-declared escape list is consulted). Commands with no absolute target, such as `ls`, are unaffected. Locked by `sec26`.

### Changed
- **BREAKING (audit wire format): host-reported handoff outcomes now audit as `execution_reported`, not `execution_finished`** (#119): `Guard::report_handoff_result` transcribes a host claim (`exit_code`, `duration_ms`) without the Guard observing execution, so it now emits the new `AuditRecord::ExecutionReported` variant; `ExecutionFinished` is reserved for executions the Guard witnessed. `guard-verify` counts the two separately. **Migration:** any consumer of the audit JSONL or SIEM stream that matches `type: "execution_finished"` will silently stop matching handoff records — those now arrive as `type: "execution_reported"` with `tool: "handoff"` and `sandbox_type: "host-handoff"`. Update matchers to handle both types; records for executions the Guard ran itself are unchanged. Locked by security regression `sec28` (no host-supplied `HandoffResult` can ever produce an `ExecutionFinished`).
- **Restricted modes now reject shell input the grammar cannot parse.** If the front-end cannot parse a command, or meets a construct it does not model, `ReadOnly` and `WorkspaceWrite` deny it: no gate could classify it, so no decision drawn from it would be truthful. This inverts the previous default, under which unrecognised syntax fell through to allow. `DangerFullAccess` is unaffected.
- **`write_file` requires an explicit workspace in `workspace_write` mode** (shipped in `72b633b`, recorded here retroactively). A missing `working_directory` is denied with `INVALID_PAYLOAD` rather than treated as unrestricted host access. **Breaking for binding users:** two-argument `decide('write_file', payload)` / `run('write_file', payload)` calls in Python and Node must now pass a context carrying `working_directory`.
- **Additional restricted-mode rejections** (shipped in `72b633b`, recorded here retroactively): opaque interpreter execution (e.g. `python3 script.py`), a parameter expansion used as the command word (`$CMD …`), multiple `find -exec`/`-execdir` actions in one command, and `env -S` / `--split-string`. `watch` payloads are re-validated as shell commands.

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
