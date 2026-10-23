# Broker Git deadline implementation checkpoint

Unreleased, in progress. User authorization: implement item 1 (Broker deadlines
and failure recovery), then "請繼續". No release, merge to main, advisory change or
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
- Draft PR **#181**, initial head `d89b5f7b32250798aa1ba269528a777924ad7258`,
  run **39879854995**, exposed an old Unix-only test assumption on Windows:
  `/tmp/repo.git` is not a Windows absolute path. Every new managed-process
  regression passed there; the existing transport-positive assertion failed.
  The fixture now uses an explicitly native absolute path and retains both
  default refusal and explicit-local acceptance, plus a file-URL control.
  No production protocol rule or required check was loosened. The first matrix
  completed **21 success / one failure** (that Windows assertion). Initial macOS,
  Linux workspace/authenticated Git and fixed-container acceptance passed;
  the corrected follow-up still requires its own complete CI, not inherited
  green checks. Full local verification, strict lint, fresh parity 70/70 and
  authenticated loopback 13/13 passed again after this test-only correction.

Sanitized results, baseline binary/log hashes and reproduction instructions are
retained in [local evidence](security-evidence/2026-10-22/broker-git-deadlines-local.json).
Full local logs remain temporary under `/private/tmp/agent-guard-deadline-*.log`.
No negative Shell strings are executed; the
only test writes are owned temporary repositories/markers with synthetic auth.

## Prerequisite integration after review

The next exact head, `77864226237c440c65204a40e1ec1928e1d1d206`, completed
[run 39880569681](https://github.com/XuebinMa/agent-guard/actions/runs/39880569681)
with 21 successes and one Windows failure: the unchanged grant race test
observed **16 successful claims for one ID**, not 16 remote writes. The
separate authorized repair is draft [PR #182](https://github.com/XuebinMa/agent-guard/pull/182),
head `63ef4d167d87ea173300e3cdfc5f9268e8df71ba`. Its own
[run 39886988969](https://github.com/XuebinMa/agent-guard/actions/runs/39886988969)
has 22/22 completed successes, including native Windows Broker/CLI and targeted
SDK approval tests. Those results do not validate an integrated deadline head.

After the user's subsequent instruction to continue, #181 incorporates that
exact prerequisite through a normal development-branch merge, preserving both
histories and the independent #182 review. Only CI step names and CHANGELOG
required conflict resolution; all checks and both behavior notes remain. The
claim and SDK production code are byte-identical to #182. No main merge, tag,
publication or advisory action is included.

The authenticated loopback tests additionally check that success, execution
query timeout, delayed acknowledgement and transport disconnect preserve both
the permanent consumed marker and archived grant, remove pending JSON and keep
the receipt's ID. Lost responses still result in one POST, `indeterminate` and
no automatic retry. These are composition assertions, not a newly claimed
standalone vulnerability. The earlier test-first commits retain the red/green
history for each production repair.

A separate read-only composition review found no actionable blocker in the
documented scope; it did not run runtime tests. The
[integrated verification record](security-evidence/2026-10-23/broker-deadline-claims-integrated.json)
separates fresh local results from hosted CI, which must be checked on the
integrated exact head. Do not borrow either parent's checks.

Fresh integrated-tree full verification exits 0: **1,235 top-level Rust passes
plus one nested child pass**, zero failures and three existing ignored
summaries. Broker **96**, CLI **24**, Python **108/one optional framework skip**,
Actions **3/3**, plugin **14/14**, scripts **52** and 92-document gates pass.
Strict all-target lint, rebuilt-binding parity **70/70** and authenticated
loopback **13/13** pass. Final evidence/documentation has its own docs gate.
The first full log completed but its old executor session was lost during
the quota interruption; a complete rerun obtained the real zero exit.

Cargo-deny passes all four categories with four existing unmatched-license and
ten duplicate-dependency warnings. Node production audit has **zero findings**;
its development/test dependency audit reports **six** (3 moderate, 2 high,
1 critical), not the earlier count. The plugin declares no runtime dependencies.
These are not claimed fixed or harmless to development: no auto-upgrade,
lockfile edit or ignored gate was added to this scoped repair.

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
