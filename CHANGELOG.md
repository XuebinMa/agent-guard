# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The `[Unreleased]` heading is rolled forward manually before each release; do not delete it.

## [Unreleased]

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
