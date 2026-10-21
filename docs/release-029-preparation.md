# 0.2.9 source preparation — not published

Checkpoint: 2026-10-21 (America/Los_Angeles).
Source candidate: **0.2.9**. Latest verified published version: **0.2.8**.

The user authorized merging the verified fixes, closing #161 after acceptance,
and preparing a successor. This does **not** authorize a tag, registry write,
GitHub Release, advisory edit or restart of the cancelled automation. This
preparation goes through its own PR and remains open for maintainer review.

## Included fixes and provenance

- [#176](https://github.com/XuebinMa/agent-guard/pull/176), main merge
  `ab55c5fcbbbbca0d97e32a181bf06df4127ae6f5`: bounded policy parser migration,
  original-byte signature/reload contracts, 43 migration regressions, exact
  Rust 1.89 policy-core gate and minimal quinn/TLS dependency-security patches.
- [#175](https://github.com/XuebinMa/agent-guard/pull/175), main merge
  `bd4b1b6087dc97e5ca8f9e7bc34f4471092d3f78`: Attenu v1/container contracts,
  parent-side required-syscall/BPF preparation and fail-closed setup diagnostics.
  Its integrated head `9a8b39b28d7cb16452c2493c3ac6b6b98027622f` passed
  [22/22 CI jobs](https://github.com/XuebinMa/agent-guard/actions/runs/39648258931).
  The Linux log actually ran 10 native unit + 14 integration tests, zero
  failed/ignored. This does not prove arbitrary-kernel or credential isolation.
- Final fix-main push CI is
  [run 39688637686](https://github.com/XuebinMa/agent-guard/actions/runs/39688637686).
  Read its actual conclusion before relying on it or closing #161; the PR's
  previous green checks are not that main-push result.

The dated [contract/seccomp report](security-review-2026-10-13.md),
[parser profile](concepts/policy-yaml.md) and [CHANGELOG](../CHANGELOG.md)
retain conditions, compatibility costs and original red/green evidence.

## Source version is not registry availability

The atomic version tool updates ten workspace package versions, every exact
local dependency pin, both Python manifests, Node metadata/lock root, plugin
metadata and current-source documentation to 0.2.9. Published README/release
links and Python installation examples remain at 0.2.8 until independently
verified publication. No historical release heading or immutable tag moves.

Compatibility changes include source Rust 1.89, 1 MiB/finite policy budgets,
explicit quoting for numeric/boolean-looking string data and Linux 3.17+
with permitted `memfd_create` for seccomp BPF export. Do not rewrite user policy
files or relax gates to hide these costs.

## Preparation acceptance

- [x] All source markers and exact local pins are 0.2.9; published markers
  remain 0.2.8. The lock graph changes only workspace package versions in this
  preparation, not dependency versions or features.
- [ ] Fresh complete `./scripts/verify.sh full`, strict all-target lint,
  format/docs/action-pin checks and 70-scenario fresh-binding parity.
- [ ] Isolated `cargo install --path ... --locked` for `guard-hook`,
  `agent-guard-cli` and `guard-verify`, matching 0.2.9 version output and
  installed-binary smoke checks with synthetic local fixtures.
- [ ] Preparation PR's own exact-head 22-job CI, including actual Linux,
  Windows, macOS, bindings/frameworks, MSRV and dependency audit/deny.

Final preparation-head checks are recorded in its PR body, not another
self-head documentation/CI commit. A source install proves this checkout and
its workspace lock build/install together; it does **not** prove that a crate
tarball exists or that registry exact-version `--locked` installation works.
No real credentials, third-party push or user global Cargo installation is
used for these checks.

## Gates reserved for later explicit publication approval

1. Review/merge the verified preparation PR. Require successful push CI on
   that exact final main SHA and recheck it is still current main.
2. Create the matching new tag only after permission. Respect release
   preflight, dependency gates and configured registry environment approvals.
   Never move `v0.2.7`/`v0.2.8` or reuse a previous tag/run.
3. Verify eight public Rust crates, all five Python wheel platforms and the
   npm plugin, hashes/contents and provenance. The Python/Node Cargo binding
   crates remain `publish = false`; the Node binding is not npm-published.
4. Independently download/install the **registry** exact-version packages
   with `--locked` in a new installation root and test actual decisions.
   Local `--path` installs are not a substitute. Do not remove exact pins or
   add temporary publication patches to work around missing new registry deps.
5. Only then update published markers and decide any warranted advisory or
   upstream communication. A merged fix is not a released fix.

Windows ambient handles, general shared-hard-link containment, Attenu
fractional TTL and unavailable future-corpus evidence remain separate. These
limitations are not converted into completed security claims by preparation.
