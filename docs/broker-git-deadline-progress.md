# Broker Git deadline implementation checkpoint

Unreleased, in progress. User authorization: implement item 1 (Broker deadlines
and failure recovery), then "請繼續". No release, merge, advisory change or
automation. Base main `6751d9fb52c3eee14e939b1dc02376efd6fe571d`; branch
`codex/broker-git-deadlines` reuses the clean independent worktree. Original
`codex/release-027-record` checkout and its dirty documents are untouched.
See the [bounded plan and references](plans/2026-10-22-broker-git-deadlines.md).

## Actual evidence so far

- The safe child-runner tests first used the old blocking wait behavior:
  two timeout/descendant regressions failed; two controls passed. These are
  runner-level failures, not a claim of an original remote exploit.
- The production runner now uses reviewed `process-wrap =10.0.1` (std,
  process-group and job-object features only), shared monotonic budgets and
  private regular-file capture with a 16 MiB per-stream limit. Nix 0.31.3
  requires libc >=0.2.186, explaining the lock's libc update. All newly selected
  dependency MSRV declarations are <=1.89; no workspace/compiler bump.
- Before changing outcome classification, the **actual current CLI** and owned
  authenticated HTTPS fixture reproduced a stronger red: remote main equalled
  the approved OID, but the delayed response yielded a `refused` receipt.
  Preview-timeout/no-grant and execution-query-timeout/spent-grant controls
  passed. Eleven of twelve host tests passed; that one failed on the wrong
  outcome, not on an unavailable option or fixture.
- After the classification patch, all twelve passed. A further immediate
  disconnect-after-update test brings the host suite to **13/13 passing**;
  it independently observes the updated ref, spent grant and exactly one POST.
- The same immediate-disconnect test was then run against the actual isolated
  registry-installed **0.2.9** CLI, without the new timeout option. The test
  failed only after independently verifying the updated ref: it observed
  `refused` instead of `indeterminate`. The final-tree CLI passes that same
  test and all 13 host tests. This is a released-binary red/green control, not
  only a new scaffold's behavior.
- Final targeted Broker/CLI/validator tests pass: 434 passes across 17 result
  groups, zero failures, one existing opt-in cost probe ignored. Stale-lease
  rejection, hostile-repository, signed receipt and ordinary push controls
  remain green.
- `./scripts/verify.sh full` exits 0 on the final production tree: 1,219
  top-level Rust passes plus one nested child pass, zero failures and three
  existing ignored summaries (the child-only probe is actually invoked by its
  parent). Python 108 pass / one optional framework skip; Node adapters,
  framework/types/native checks, Actions 3/3 and plugin 14/14 pass. The 52
  script tests and 90-document, version and action-pin gates pass.
- Strict workspace/all-features/all-targets Clippy exits 0. Fresh Python and
  Node bindings match Rust on all **70** parity cases. The first fresh Python
  build hit inherited Conda/venv ambiguity; removing `CONDA_PREFIX` for that
  command resolved it. An initial comparator invocation used the wrong working
  directory; the corrected repository-root run passed. No gate was weakened.
- `cargo deny check`: advisories/bans/licenses/sources all pass with the new
  dependency graph. No advisory ignore or weakened gate.
- One new output-limit test initially hit a cleanup EPERM after its very fast
  child exited. Cleanup stayed a hard error. Its finite fixture now stays alive
  briefly to test output-limit termination specifically; no EPERM is suppressed.
  New fixture code was corrected to wait for its owned child, satisfying strict
  Clippy rather than disabling the zombie-process lint.

Sanitized results, baseline binary/log hashes and reproduction instructions are
retained in [local evidence](security-evidence/2026-10-22/broker-git-deadlines-local.json).
Full local logs remain temporary under `/private/tmp/agent-guard-deadline-*.log`.
No negative Shell strings are executed; the
only test writes are owned temporary repositories/markers with synthetic auth.

## Remaining before review/merge

- Final runner/outcome diff received a separate read-only source review; no
  blocking defect was found. That review did not rerun tests or prove native
  platform behavior. Final evidence/documentation, version/action pins and
  whitespace checks pass before the normal commit and draft PR.
- Native Linux and Windows runtime results are **unrun locally**. Existing
  macOS/Windows CI jobs now include Broker/CLI runtime tests; prior CI on an
  unchanged release source cannot substitute for this new head.
- Exact committed head and hosted checks are tracked in the draft PR, not
  self-referential documentation commits. No merge or release is authorized;
  no current version/tag/published marker changed.
- Existing Windows ambient handles, general shared-hard-link containment,
  credentials as a deployment property, physical snapshot I/O and detached
  malicious trusted helper limits remain explicit. This is not OS containment.
  The reviewed Windows wrapper does not set kill-on-job-close; explicit
  managed-child cleanup handles ordinary completion/unwinding, not abrupt
  broker death. Do not claim a new parent-death guarantee.

Old pushed/refused v1 preimages are byte-locked. New `indeterminate` outcomes
retain the exact transaction and consumed grant; old exhaustive readers must
handle or reject the added variant. The CLI exits 3 and asks for independent
read-only reconciliation, never automatically pushing again or reviving a grant.
