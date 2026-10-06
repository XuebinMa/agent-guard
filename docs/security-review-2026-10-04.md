# Defensive security review — 2026-10-04

Status statements below describe the frozen local review before submission.
For subsequent PR, CI and release progress, see the
[delivery record](security-delivery-2026-10-04.md).

## Scope and evidence boundary

Baseline: `origin/main` / `v0.2.6` at
`4dc4bb3151c483acdda945466cdb478d667d94c1`. The initial local checkout had the
same tree. Local remediation branch: `codex/security-review-026`.
No merge, push, release, registry publication, or advisory mutation is part of
this review. Patches are **unreleased**. The subsequent integration also reviews
PR [#170](https://github.com/XuebinMa/agent-guard/pull/170), head
`fd2c391823c683c6f57cfc43804914c3a090acc7`, against that same baseline.

GitHub reports 19 completed/successful checks on that PR head; it remains a
draft with no reviews or comments. Those checks do not validate this local
combined tree. The original local 15 fixes and #170 are separate patch sets.

## Integration plan and evidence

1. Preserve the original 15 fixes and all their negative/positive regressions.
   Incorporate #170's broker and validator changes locally; reconcile overlapping
   AST, sed, path, read-only, and regression-test edits. Keep local `sec35`/`sec36`;
   number the PR cases `sec37`–`sec39` and the new alias/config lock `sec40`.
2. Close the verified alias/config gaps: retain inherited config at every alias
   expansion, fail closed on unmodeled shell argument forwarding, recover quoted
   declaration assignments, and retain conservative intent for opaque
   environment-provided aliases.
3. Keep the bounded sed parser; refuse attached external scripts and opaque
   ripgrep configuration in read-only mode. Interpret actual option/value
   positions so searching for an option name remains a valid read-only action.
   Check decoded environment-wrapper arguments before stripping their launcher.
4. Disable HTTP redirects in every sanitized broker Git command. Test config
   precedence with a synthetic header and local endpoints; correct the remote-ref
   test so its decoy sorts first, and add a missing-branch/decoy-present case.
5. Run the combined validator, broker, SDK regression and lint gates, then
   `./scripts/verify.sh full`. Record its actual exit status and run bindings/parity
   against rebuilt native modules. Native Linux/Windows CI remains required on
   the eventual submitted commit.

Before patching, the isolated #170 source snapshot failed **8 of 10** additional
validator decisions and **all 5** additional SDK policy decisions. The two
passing validator controls were the separated sed-script refusal and an ordinary
ripgrep search. The failures covered inherited alias/config loss, forwarded
arguments, quoted environment declarations, attached sed scripts, opaque ripgrep
config, option-name search data, and the pre-existing sed destination gap.
The SDK returned `Allow` twice and `AskUser` three times where the test policy
required `Deny`. No command strings in these tests were executed.

The original remote-tip regression in #170 put its decoy after the exact branch,
so the old first-line parser also passed. The replacement fixture must sort its
decoy first to establish red-to-green evidence.

Reviewed Git transaction/snapshot/config/grant/receipt handling, shell AST and
write-target classification, policy and approval transitions, SDK execution,
Python/Node integration surfaces, local audit persistence, and offline evidence
validation. Tests use temporary local repositories/files, harmless output and
short sleeps, synthetic keys, and decision-only negative inputs. No live remote
pushes, real credentials, destructive payloads, or third-party probes were used.

This is a focused multi-module review, not a proof that every repository line or
every platform is secure. Local execution is macOS. Linux enforcement and Windows
launch behavior still need their native CI runners. Default/noop and decision-only
hook behavior are not upgraded into containment claims by these fixes.

Severity is contextual, not a CVSS assignment. High findings bypass an advertised
decision boundary under the stated preconditions; medium/low findings affect
evidence integrity or availability. No new critical broker credential-execution
finding was established.

**Local remediation outcome:** 22 findings are patched with permanent regression
coverage (9 high, 12 medium, 1 low). R1 (Windows ambient handles) and R2 (shared
hard-linked inodes) remain open; documentation is not counted as their fix.
The combined tree is not submitted, merged, or released.

## Confirmed and patched findings

### F1 — High: policy can change while a broker confirmation waits

- **Path:** `agent-guard-cli/src/main.rs::run_push`.
- **Condition/impact:** the user previews a local transaction; the host then
  tightens or removes the policy while confirmation waits. The old in-memory
  policy could still issue a grant and update the local test remote.
- **Patch:** reload after confirmation, before grant issuance; fail on read/load
  failure or any policy-version change and require a new preview. The grant,
  exact OID/URL, remote lease, and isolated execution repository remain intact.
- **Regression:** [push_policy_revalidation.rs](../crates/agent-guard-cli/tests/push_policy_revalidation.rs)
  tests tightened, removed, and unchanged policies using the actual CLI and a
  temporary bare remote. The tightened-policy case failed before the patch.
- **Boundary:** this is revalidation after human waiting, not continuous policy
  revocation after the execution snapshot has been selected.

### F2 — High: ANSI-C word decoding can disagree with shell command identity

- **Path:** `agent-guard-validators/src/bash/ast.rs`, static word decoding.
- **Condition/impact:** a caller controls a Bash payload under a restricted mode.
  Decoded NUL fragments and byte/locale ambiguities could leave a different word
  in the classifier than the shell interprets, missing a controlled executable
  or Git subcommand. No command was executed to validate the negative cases.
- **Patch:** reject decoded NUL and unsupported/non-ASCII escaped fragments;
  model octal byte truncation, including an octal value wrapping to zero.
- **Regression:** `sec35_ansi_c_nul_words_cannot_hide_controlled_commands` in
  [security_regression.rs](../crates/agent-guard-sdk/tests/security_regression.rs),
  plus existing positive static-word normalization tests. Baseline returned
  `Allow` for a negative test; the patched decision is `Deny`.

### F3 — High: sed in-place and secondary write destinations were not checked

- **Path:** `bash/paths.rs`, `read_only.rs`, and the new bounded `sed.rs` parser.
- **Condition/impact:** a Bash payload names an existing file outside the
  workspace. No sed arm extracted its in-place destination; attached backup
  flags also escaped the read-only flag check. Secondary script I/O was opaque.
- **Patch:** parse common inline scripts/options; pass in-place files through
  workspace checks; reject external scripts, secondary I/O/execution, unsafe
  backup suffixes, and unsupported syntax. Finish option parsing before assigning
  the positional script so a late `-e` cannot hide an earlier filename.
- **Regression:** `sec36_sed_in_place_targets_are_confined_and_read_only_is_preserved`
  and [sed.rs](../crates/agent-guard-validators/src/bash/sed.rs) unit tests cover
  GNU/BSD forms, attached suffixes, late expressions, secondary destinations,
  and a positive in-workspace edit decision. Negative inputs are decision-only.
- **Compatibility:** common transformations remain supported; this is not a
  complete sed interpreter. Some formerly accepted harmless complex scripts
  now fail closed. General shell containment still requires an OS boundary.
- **Integration:** #170's separate `sed -f` check missed attached `-fPATH` and
  retained the baseline destination gap. The bounded parser is preserved in the
  combined tree and both forms receive the same refusal.

### F4 — High: approval resume skipped current subject lock/rate state

- **Path:** `agent-guard-sdk/src/enforce.rs::resume_execution`, `anomaly.rs`.
- **Condition/impact:** a request is pending, then another request locks or rate
  limits the same host-supplied subject. Approval previously rechecked policy but
  not this state, and could execute a benign local write after lockout.
- **Patch:** recheck current subject state before approved execution without
  recording the pending request a second time.
- **Regression:** [approval_resume.rs](../crates/agent-guard-sdk/tests/approval_resume.rs)
  covers lockout, rate limiting, and the positive one-call/no-double-count case.
  Both refusal tests failed before remediation.

### F5 — Medium: custom tool deserialization bypassed constructor invariants

- **Path:** `agent-guard-core/src/types.rs::CustomToolId`.
- **Condition/impact:** a Rust host deserializes tool identifiers and dispatches
  by their displayed name. Derived deserialization accepted reserved builtin
  names as custom tools, which can take the custom handoff path rather than the
  builtin execution policy. Ordinary validated constructors were not affected.
- **Patch:** custom `Deserialize` delegates to `CustomToolId::new`.
- **Regression:** [security_input_boundaries.rs](../crates/agent-guard-core/tests/security_input_boundaries.rs)
  rejects invalid/reserved IDs and preserves valid custom/builtin wire formats.

### F6 — Medium: Unix pipe draining could exceed the execution deadline

- **Path:** `agent-guard-sandbox/src/process.rs::wait_for_child/read_bounded`.
- **Condition/impact:** another writer retains an output-pipe handle. Even after
  the child exits or is terminated, blocking readers awaited EOF beyond timeout.
- **Patch:** Unix capture uses nonblocking read ends and cancellation shared with
  the lifecycle loop, including error exits; byte-retention limits still apply.
- **Regression:** `deadline_bounds_output_drain_when_an_unrelated_writer_remains_open`
  in [process.rs](../crates/agent-guard-sandbox/src/process.rs) holds a duplicate
  writer in the test harness for 750 ms. A 100 ms timeout previously took about
  759 ms; patched execution returns within the test's 500 ms bound. Existing
  output-limit, capture, descriptor-hygiene, and group-cleanup tests remain.
- **Boundary:** this bounds Unix capture; it does not eliminate detached-process
  or kernel uninterruptible-I/O limitations, and does not validate Windows.

### F7 — Medium: concurrent JSONL writers corrupted audit/approval frames

- **Path:** SDK `approval.rs::append/fold`, `audit_writer.rs::run_worker`.
- **Condition/impact:** independent Guard/ledger writers share one file.
  Formatted JSON and its newline used separate writes, allowing interleaving;
  approval replay skipped corrupted records and audit evidence was lost.
- **Patch:** complete frames plus exclusive advisory file locks; approval reads
  use shared locks. Lock acquisition has a two-second bound and returns errors.
  The [fs2 file-lock API](https://docs.rs/fs2/latest/fs2/trait.FileExt.html) is used
  instead of inventing platform-specific locking. Cargo.lock includes the pin.
- **Regression:** [jsonl_concurrency.rs](../crates/agent-guard-sdk/tests/jsonl_concurrency.rs)
  checks 1,200 events from independent threaded writers and 400 pending events
  from four processes. Both threaded baseline tests produced malformed JSON.
- **Boundary:** cooperating local writers only; no authentication, crash recovery,
  network-filesystem guarantee, or removal of existing audit backpressure drops.

### F8 — Low: extreme anomaly windows panicked clock arithmetic

- **Path:** core policy validation and SDK `anomaly.rs` window pruning.
- **Condition/impact:** a host supplies an unrepresentable policy window; a later
  check panicked on `Instant - Duration`. This is a configuration/availability
  issue, not an arbitrary Bash payload privilege escalation.
- **Patch:** reject unrepresentable file configuration; direct detector APIs use
  saturating elapsed durations so large values cannot panic or disable limits.
- **Regression:** core `anomaly_windows_outside_the_supported_clock_range_fail_at_load_time`
  and SDK `unrepresentable_windows_in_direct_config_never_panic_or_disable_limits`.

### F9 — Medium: Python awaitables were reported successful before execution

- **Path:** Python `openai.py::wrap_openai_tool`, `adapters.py::dispatch_via_run`.
- **Condition/impact:** a host tool handler is async or returns an awaitable.
  Creating the coroutine was recorded as success before the body ran; a later
  exception could not be represented by the consumed terminal report.
- **Patch:** async handlers use async dispatch; returned awaitables report only
  after actual completion/failure, preserving existing reporting-error behavior.
- **Regression:** [test_async_lifecycle.py](../crates/agent-guard-python/tests/test_async_lifecycle.py)
  covers native Guard with coroutine and awaitable-returning callbacks, successful
  results, and harmless fixture exceptions. Four cases failed on the baseline.

### F10 — Medium: cancelling a waiter prematurely finalized a live host action

- **Path:** Python `adapters.py::dispatch_via_run_async` sync callback path.
- **Condition/impact:** cancelling the asyncio waiter did not stop its worker
  thread, but emitted a failure and consumed the request while the callback
  continued. A subsequent real outcome was lost or contradictory.
- **Patch:** the synchronous check/dispatch/callback/report lifecycle stays in
  one worker. Cancellation affects the waiter, not the real terminal report.
- **Regression:** the same Python file covers cancellation followed by actual
  success/failure using bounded events and an in-memory marker only.
- **Boundary:** no claim of thread cancellation or reporting durability on host
  process termination; hosts must not retry merely because waiting was cancelled.

### F11 — Medium: blocking native calls held the Python GIL

- **Path:** PyO3 `types.rs` Guard execution/decision/report wrappers.
- **Condition/impact:** even `asyncio.to_thread` could stall the Python event
  loop during synchronous Rust execution, delaying host supervision/timeouts.
- **Patch:** detach from Python for native Guard operations and reacquire before
  converting results. Existing Rust synchronization remains authoritative.
- **Regression:** native `execute` and `run` with a short harmless sleep must
  permit another Python event-loop task to tick; both cases were red before the
  patch. All eight new Python lifecycle cases passed after a native rebuild.

### F12 — Medium: Attenu comparisons discarded constraint identity

- **Path:** `guard-verify/src/attenu/authority.rs::parse_constraint/contains`.
- **Condition/impact:** an integrity-valid bundle changes a constraint's field,
  scope, or type while making its numeric/set value look narrower. The verifier
  could incorrectly accept that delegation. This is an offline evidence defect,
  not an automatic broker authorization path.
- **Patch:** retain exact type/selector identity alongside the monotone limit;
  compare limits only when identities agree. Unknown constraints remain opaque.
- **Regression:** [value_boundary_tests.rs](../crates/guard-verify/src/attenu/value_boundary_tests.rs)
  reseals synthetic allow/deny/prefix/max-calls mutations, selector removal/type
  changes, and positive same-selector narrowing. The published corpus is intact.

### F13 — Medium: a valid signature could bless an invalid observation shape

- **Path:** `guard-verify/src/attenu/envelope.rs::judge`.
- **Condition/impact:** a trusted fixture signer signs an absent/scalar
  `observed`, unknown result, or ill-typed optional metadata; the old verifier
  reported witness-signed despite not understanding the observation contract.
- **Patch:** require an object and the closed result vocabulary; optional `at`
  and `method`, when present, must be strings. No new authority is inferred from
  `matched`, `not_matched`, or `indeterminate`.
- **Regression:** the same test file re-signs each mutation with a synthetic key
  and checks rejection plus `process-asserted`; all three valid results pass.
- **Contract:** the [upstream vectors description](https://github.com/attenu-io/attenu-guard/blob/main/tests/vectors/README.md)
  defines the vocabulary. `envelope_invalid_observation` is explicitly a local
  extension outside its pinned seven-reason corpus, not a claimed upstream token.

### F14 — High: Node ToolCall metadata hid the actual policy arguments

- **Path:** Node `adapters.js::wrapLangChainTool`.
- **Condition/impact:** LangChain `invoke` accepts both bare input and a `ToolCall`
  envelope. The wrapper checked the envelope, then its one-use framework ticket
  skipped checks as LangChain unwrapped `args`. An anchored deny over actual
  arguments was missed, although the equivalent bare input was denied.
- **Patch:** normalize `ToolCall.args` before payload construction while preserving
  the original envelope for framework invocation and result formatting. Malformed
  argument containers fail closed; trusted payload mappers receive action args.
- **Regression:** `testLangChainToolCallArgumentsHaveTheSamePolicyAsBareInput` in
  [test-frameworks.js](../crates/agent-guard-node/test-frameworks.js) runs real
  `DynamicTool` in check/auto modes, asserting no callback on both denied forms
  and a correct ToolMessage for the allowed form. The only action is appending
  a harmless string to an in-memory array; the envelope rejection was red first.
- **Boundary:** arbitrary host-provided schema transforms/payload mappers remain
  trusted application logic; this is not a universal framework-interpreter proof.

### F15 — Medium: failed plugin installation registered an old PATH binary

- **Path:** `packages/agent-guard-plugin/bin/cli.js::cmdInit`.
- **Condition/impact:** an old binary is found and exact-version installation
  fails. `installOne` correctly returned null, but setup then registered the bare
  `guard-hook` command, silently selecting that old binary on later hook calls.
- **Patch:** abort non-dry-run setup before policy/settings writes if either
  exact-version binary is unavailable. The user-requested `--skip-binary` opt-out
  remains explicit; this does not change the runtime hook's fail-open contract.
- **Regression:** [init.test.js](../packages/agent-guard-plugin/test/init.test.js)
  runs the real CLI with fake version/install results and a temporary home.
  Normal and binary-only setup must fail with existing settings unchanged and no
  new policy. No Cargo command, registry write, or user configuration is touched.

### F16 — High: Git grammar/config/alias recognition could weaken outbound decisions

- **Path:** `bash/git_push.rs`, `ast.rs::environment_writes`.
- **Condition/impact:** a host relies on canonical push subjects, and a caller
  uses abbreviated flags, command-line/opaque environment config or an alias.
  Destructive subjects could disappear; additional #170 tests demonstrated two
  `Allow` decisions and three ordinary approvals in place of required refusals.
  This affects the decision gate; it does not bypass the broker's credential
  isolation or authorize a different broker transaction.
- **Patch:** preserve destructive flag/config semantics, inherit config across
  alias recursion, recover quoted/concatenated declarations, and conservatively
  classify runtime-dependent shell aliases and opaque-config invocations.
- **Regression:** `sec37` and `sec40`, plus `git_push/tests.rs` and AST tests,
  cover static/recursive/dynamic aliases, config precedence and quoted exports.
  Existing static alias and ordinary-push positive controls remain.
- **Compatibility:** opaque injected Git config and dynamic shell aliases may
  conservatively receive destructive classifications even for benign actions.
  This remains an intent classifier, not a complete shell/Git interpreter.
  Programs/scripts invoked by static aliases and repository/user config outside
  the command remain outside its inspected argv; use the broker for a credential
  boundary rather than inferring containment from an absent push subject.

### F17 — High: shell expansion could turn an accepted path component into a parent

- **Path:** `bash/paths.rs::check_target`.
- **Condition/impact:** a restricted-mode command supplies a target whose brace
  expansion or dot-glob yields a `..` component after lexical path validation.
  Actual matching depends on shell behavior and directory contents.
- **Patch:** refuse brace expansion and glob components that can match the parent
  before normal path/escape-list checks.
- **Regression:** `sec38` and `bash_shell_expansion_target_tests`; ordinary file
  globs, placeholders and explicit in-workspace paths remain positive controls.
- **Compatibility:** quoted literal filenames containing brace expansion syntax
  may be refused because the AST target does not retain their quote provenance.

### F18 — High: read-only program options/configuration hid an executable action

- **Path:** `bash/read_only.rs`, `tables.rs`, and bounded `ripgrep.rs`.
- **Condition/impact:** the host executes an allowlisted read-only command whose
  argv/environment chooses a helper program or an opaque configuration file.
  Prefix/quoted declarations and decoded `env` arguments could evade raw scans.
  F3 independently covers sed scripts and file destinations.
- **Patch:** inspect AST-normalized assignments before wrapper removal, include
  loader variables and declaration/append assignments, refuse opaque ripgrep
  config, and parse option values before deciding where `--` terminates options.
  Unknown ripgrep options fail closed in read-only mode.
- **Regression:** `sec39` and `bash_read_only_exec_vector_tests` include compact
  sed script flags, decoded wrapper assignments, ordinary searches, option names
  as data, and a `--` consumed by `-e` rather than ending option interpretation.
  The normalized-wrapper test was observed returning `Allow` before the fix.
  Decoded assignment-looking operands of ordinary commands remain data, as locked
  by positive direct/nested `find -exec` echo controls; inspection is confined to
  the removed wrapper prefix, located by the child slice's start rather than its
  length because `find` also removes trailing action tokens.
- **Boundary:** inherited host environment and arbitrary executable behavior
  remain host trust/OS-isolation concerns; this is visible-input classification.

### F19 — Medium: remote-tip query could select a suffix-matching sibling ref

- **Path:** `agent-guard-broker/src/transaction.rs::resolve_remote_oid`.
- **Condition/impact:** `ls-remote` returns another full ref ending in the queried
  branch name. Taking the first line gave an incorrect preview/lease tip or
  treated a missing branch as an update. Existing push leases may then reject;
  this review does not claim a different URL receives the push.
- **Patch:** select the exact full `refs/heads/<branch>` output; separate Git
  positional arguments with `--`.
- **Regression:** [transaction.rs](../crates/agent-guard-broker/tests/transaction.rs)
  uses an earlier-sorting decoy and a decoy-only/missing-branch case. Both failed
  under the old first-line parser; #170's original later-sorting decoy did not.

### F20 — Medium: non-printable/Unicode URL text could mislead approval display

- **Path:** `agent-guard-broker/src/git/validate.rs::validate_remote_url`.
- **Condition/impact:** repository-controlled URLs contain bidi/control or
  visually confusable non-ASCII text. A human may approve a misleading preview.
- **Patch:** require printable ASCII URL bytes in the supported transports.
- **Regression:** transport and non-ASCII/control unit cases, with accepted
  HTTPS/SSH/SCP-style positives. This does not claim all ASCII URLs are visually
  unambiguous; users must still inspect the resolved destination.

### F21 — High: preview headers lacked destination scope and redirect isolation

- **Path:** broker trusted-config validation and `git/command.rs`.
- **Condition/impact:** a host explicitly configures a credential-bearing
  `http.extraHeader`; preview contacts a repository-selected URL before approval.
  Unscoped headers can go to an unintended host. Even scoped custom headers can
  follow an HTTP redirect after matching the initial URL.
- **Patch:** require explicit URL header scopes, pin `http.followRedirects=false`
  for all sanitized commands and reject generic/URL-scoped redirect overrides.
  [Git's configuration reference](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpfollowRedirects)
  specifies redirect refusal and that redirected URLs are not rematched against
  the original URL-scoped configuration.
- **Regression:** config rejection/precedence tests and actual Git loopback
  redirect test with the public `X-Agent-Guard-Canary` value. Before the patch the
  target received that canary; afterward it is not contacted. HTTP is enabled
  only for the private test command; public broker protocol defaults stay strict.
- **Boundary:** helpers, SSH configuration, the dedicated config and credentials
  remain trusted host resources; these tests use no real secrets.

### F22 — Medium: grant persistence exposed authorization data and normalized IDs

- **Path:** `agent-guard-broker/src/grant.rs`.
- **Condition/impact:** Unix grant files/directories had ambient default
  permissions; another local identity could read grant data. Raw separator/dot
  ID spellings were inconsistently accepted after path normalization. No claim
  is made that those spellings alone authorized a different transaction.
- **Patch:** strict raw ID grammar, atomic private-file persistence, and `0700`
  grant directories with `0600` files on Unix.
- **Regression:** [grant.rs](../crates/agent-guard-broker/tests/grant.rs) rejects
  separator/dot IDs and proves private permissions from an initial `0755`
  directory. Existing single-use/concurrent-spend tests remain. Same-permission
  host process trust is unchanged; Unix permission tests are platform-specific.

## Remaining findings and deployment limits

### R1 — High priority before enabling Windows isolation: ambient handles

`windows.rs::spawn_low_integrity_process` calls `CreateProcessAsUserW` with handle
inheritance enabled and `STARTUPINFOW`, without `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
An already-inheritable parent handle can carry authority independent of a low
integrity token. The current `test_windows_handle_inheritance_audit` checks only
that a normal file handle is non-inheritable by default.

**Status:** source-confirmed exposure; no Windows execution reproduction or patch
in this macOS pass. **Proposed patch:** extended startup information containing
only intended stdio handles; ensure every fallback preserves the same restriction
or fails closed. **Regression:** on a Windows runner, intentionally mark a handle
to a temporary fixture inheritable and verify the child cannot use it while its
intended pipes still work. Do not call the existing default-handle test sufficient.

### R2 — Medium, deployment-dependent: shared-inode hard-link aliases

Capability-relative `execute_workspace_write` correctly blocks path/symlink
traversal, but writing an existing hard-linked inode also changes its outside
alias. A local two-directory fixture reproduced this. **Status:** not fixed;
documented explicitly in the threat model. Avoid shared writable inodes across
trust boundaries. **Proposed design:** consider copy-and-atomic-replace semantics
for overwrite/append, including metadata/ownership and concurrency requirements;
a check of `nlink` alone is not a race-safe solution. **Regression plan:** two
temporary directories with one linked file; verify outside content remains intact
under the chosen semantics, with concurrent mutation tests before claiming closure.

### Operational items not promoted into unproven vulnerabilities

- Broker snapshot size/time and Git network subprocess budgets need representative
  large-repository and stalled-local-endpoint tests. No new arbitrary cutoff was
  introduced in this patch.
- The dependency audit reported `RUSTSEC-2026-0190` (`anyhow` 1.0.102) and
  `RUSTSEC-2026-0221` (`event-listener` 5.4.1) as informational unsoundness warnings.
  The lockfile now selects 1.0.103 and 5.4.2 respectively; a fresh `cargo audit`
  reports zero vulnerabilities and no warnings. `event-listener` is reached
  through the test-only `httpmock` dependency; this review did not demonstrate
  a reachable production misuse of either affected API.
- npm's development tree reports four advisories (one high, three moderate) in
  `fast-uri`, `hono`, `ip-address`, and `qs`. The Node production-only audit is
  clean; these framework-test dependencies are not promoted to runtime dependencies.
  The plugin manifest has no dependencies; direct `npm audit` there has no lockfile
  and therefore was not reported as a successful scan. No broad npm upgrade was made.
- Hook fail-open behavior, same-user editable ledgers, trusted host identity,
  process-group rather than cgroup containment, and broker PATH/HOME/SSH/config
  trust assumptions remain deployment limits, not newly closed vulnerabilities.

## Release/advisory follow-up

The published [GHSA-j64p-f672-v3jq](https://github.com/XuebinMa/agent-guard/security/advisories/GHSA-j64p-f672-v3jq)
was read through GitHub's API during this review. It states that 0.2.6 models sed
destinations and marks only versions through 0.2.5 affected. F3 disproves that
part of the fix claim on the release tree. Correct that claim/affected range in
coordination with a tested follow-up release; do not label this uncommitted patch
as an available fix. No advisory/CVE or registry record was modified here.

## Verification

Targeted negative tests were observed failing before each corresponding fix,
then rerun after the patch. Final full-gate results are recorded below only after
the run completes; partial logs do not count as an exit-zero claim.

- Targeted: broker policy confirmation 3/3; SDK approval resume 12/12; core input
  boundaries 3/3; JSONL concurrency 4/4; Unix process lifecycle 6/6 (including the
  descriptor observer helper); guard-verify
  70/70; validators 324 unit + 3 corpus tests; Python 108 passed / 1 skipped after
  native rebuild. Later full verification supersedes interim counts.
- Node real-framework tests pass with the ToolCall negative/positive cases, and
  plugin tests pass 13/13 with normal and binary-only installation failure cases.
- `cargo clippy --workspace --exclude agent-guard-python --all-features --all-targets -- -D warnings`:
  passed after fixing a test-only import and MSRV-compatible lint suggestions.
- Python binding `cargo clippy -p agent-guard-python --all-targets --no-deps --
  -D warnings`: passed. The separate cross-language comparator passed **16/16**
  scenarios with matching Rust, Python, and Node decisions on freshly built bindings.
- Pre-integration frozen-code `./scripts/verify.sh full`: **exit 0**. Rust reported 49
  result groups with **1,033 passed, 0 failed, 2 ignored**; Python **108 passed,
  1 skipped**; Node type/adapter/real-framework/native/example tests and plugin
  **13/13** passed. Documentation/version/workflow checks passed again after
  report edits. Ignored/platform-gated tests and the skipped Python framework
  module are not evidence of coverage on those surfaces.
- Final `cargo audit`: **exit 0, 0 vulnerabilities, no warnings**. `cargo deny
  check`: **exit 0** (advisories, bans, licenses, sources). Node production-only
  `npm audit`: **exit 0, 0 findings**; the four dev-only npm warnings remain.
- Local full-run log: `/tmp/agent-guard-review-026-verified-full.log`; dependency
  evidence: `/tmp/agent-guard-review-026-cargo-audit-final.json` and
  `/tmp/agent-guard-review-026-cargo-deny-final.log`. These are session artifacts,
  not portable proof files or a substitute for rerunning CI on the eventual PR.
- The first full run failed an existing descriptor test's shell exit-code
  assertion. An isolated run and 20 repeated parallel unit-suite runs passed,
  so the precise cause of that intermittent exit status was not established.
  The test now observes the fixture's device/inode directly in a child test
  process, with a no-hygiene negative control. Both controls pass without changing
  the production descriptor-hygiene code; the full gate is rerun, not skipped.

The results above apply to the original local patch set, before #170 integration.
They must not be presented as verification of the combined tree.

### Combined-tree final verification

The code was frozen after the final `find -exec` prefix correction. Tests below
ran on that combined tree; subsequent edits only record documentation evidence.

- Environment: macOS 26.6.2, Git 2.49.0, Rust 1.94.1, Python 3.14.2, Node 25.6.0,
  ripgrep 15.2.0. This is not an execution test of Rust's 1.79 MSRV, Node's CI
  20/22 matrix, or Linux/Windows enforcement. Native-platform CI must run on the
  eventual combined commit, not merely #170's existing head.
- `AGENT_GUARD_PY_FRAMEWORKS=langchain-core ./scripts/verify.sh full`: **exit 0**.
  Rust reported **49 result groups, 1,069 passed, 0 failed, 2 ignored**. This
  includes **347 validator unit tests + 3 corpus tests**, **50 SDK security
  regressions**, and **57 broker tests**. Counts are reported test executions,
  not a claim of 1,069 distinct security properties.
- Python with real **LangChain 1.6.6: 113 passed, no skips**. A separate
  `AGENT_GUARD_PY_FRAMEWORKS='langchain-core>=0.3,<0.4' ./scripts/verify.sh python`
  resolved **0.3.86** and also returned **exit 0, 113 passed, no skips**. Both
  rebuild the actual PyO3 module; mocks do not replace native decision tests.
- Node type, adapter, real-framework and native tests passed; local example
  tests passed **3/3** and plugin tests **13/13**. The four dev-only npm advisories
  still appear during `npm ci`; this is not a claim of a clean development tree.
- Final strict lint: workspace `--all-features --all-targets -- -D warnings`
  (excluding the Python extension-module crate), plus separate Python binding
  `--all-targets --no-deps -- -D warnings`, both **exit 0**.
- Freshly rebuilt Rust/Python/Node decision surfaces match on **30/30** shared
  scenarios. Desired allow/deny behavior is separately locked by unit/SDK tests;
  equality alone is not treated as proof that a shared wrong decision is safe.
- Full-gate documentation, version and pinned-workflow checks passed, including
  **22 script tests** and **202 Markdown files**. Formatting and diff whitespace
  checks passed; documentation gates are rerun after this evidence update.
- The first combined full run stopped at two Clippy warnings; they were fixed
  without weakening the gate or raising the MSRV. The independent final review
  then found the truncated `find -exec` child false positive: the new test was
  observed failing before its prefix correction, and direct/nested echo positive
  controls plus a wrapped dangerous-environment negative control now pass.
  The full gate was rerun after that code change.
- Session evidence: `/tmp/agent-guard-pr170-integrated-frozen-full.log`,
  `/tmp/agent-guard-pr170-integrated-final-lint.log`,
  `/tmp/agent-guard-pr170-integrated-final-parity.log`, and
  `/tmp/agent-guard-pr170-integrated-python-03.log`. These are local run artifacts,
  not portable signed evidence or replacements for CI on the submitted commit.

No commit, push, PR transition, release, or advisory update was performed. R1/R2
remain open, and the sed advisory correction still requires a tested release.

## Implementation references

- [Git HTTP configuration](https://git-scm.com/docs/git-config) provides the
  supported redirect control and URL matching rules; no independent header
  forwarding heuristic was substituted for Git's own transport behavior.
- [ripgrep flag definitions](https://github.com/BurntSushi/ripgrep/blob/master/crates/core/flags/defs.rs)
  and [argument parser](https://github.com/BurntSushi/ripgrep/blob/master/crates/core/flags/parse.rs)
  were consulted alongside the installed binary's help and safe argument probes.
  The restricted-mode parser models the needed option/value boundary and
  refuses newer/unknown options rather than claiming complete ripgrep semantics.
