# Permanent one-use grant claim repair

Status: in progress, unreleased. The maintainer explicitly authorized this
separate prerequisite after the Broker deadline review exposed a Windows
grant race. Base main: `6751d9fb52c3eee14e939b1dc02376efd6fe571d`.
Work remains in the independent checkout on `codex/grant-claim-fence`.
Do not merge/release, alter advisories or restart cancelled automation.

## Evidence and scope

PR #181 head `77864226237c440c65204a40e1ec1928e1d1d206`,
[run 39880569681](https://github.com/XuebinMa/agent-guard/actions/runs/39880569681),
finished 21 success / one failure. The existing unchanged Windows regression
`concurrent_spenders_produce_exactly_one_winner` observed **16 successful grant
claims** for the same ID. It does not prove 16 remote writes; the exact
transaction and remote lease are separate defenses. New native CI coverage
exposed the previously unrun invariant. Neither the grant implementation nor
that race test differs from v0.2.9, but affected published compiler/build
combinations have not been exhaustively backtested.

The fix changes grant claiming/evidence retention, its tests and required
native verification. The native gate also exposed an existing CLI approval
ledger handle-access failure; a separate minimal Windows-only compatibility
commit preserves its existing locks and Unix write-only access. No other SDK
behavior, deadline-runner dependency, new service, grant schema, receipt schema
or signing format changes. Keep #181 draft until
its prerequisite and integrated exact head pass review/CI.

## Existing implementation references

- [Git 2.49 lockfile API](https://github.com/git/git/blob/v2.49.0/lockfile.h)
  establishes writer exclusion through exclusive creation before replacement.
  Reuse that narrow primitive, not its temporary-lock deletion lifecycle.
- [Rust OpenOptions::create_new](https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#method.create_new)
  is atomic and refuses existing entries, including dangling links.
- [Windows CREATE_NEW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
  fails if the requested file already exists. No new library is required.

## Invariants

1. Atomically create `spent/claim-<entire-id>.consumed` before any grant read,
   archive rename, repository inspection or Git call. Only that winner proceeds.
2. Never remove the marker on validation, I/O, archival failure, success or
   process exit. A marker is an irreversible consumption slot, not a lease.
3. Detect legacy spent entries without following links. Any existing entry
   blocks replacement; inspection failures refuse rather than imply absence.
4. Preserve the consumed ID in execution receipts even when no archive was
   produced. Old JSON schemas/ordinary successful execution remain compatible.
5. Stop old consumers on upgrade; do not claim protection against mixed old/new
   binaries, writable authority stores, whole-store rollback or power loss.

## Sequence and gates

- [x] Preserve the existing 16-thread test unchanged and the actual Windows
  failure; add negative lifecycle tests first as a separate local commit.
- [x] Baseline local red: nine new assertions fail, one helper control passes.
  Some failures are new-marker contract assertions, not nine distinct exploits.
- [x] Implement exclusive reservation with private marker permissions, retained
  archives and no cleanup/removal path.
- [x] Real independent-process contenders, abrupt process exit after the actual
  production reservation, marker-only receipt and invalid/legacy states.
- [x] Full local gates, strict all-target lint, fresh bindings/parity and normal
  authenticated loopback positive/negative controls. See the
  [verification checkpoint](../grant-claim-progress.md).
- [ ] Exact-head native CI; local macOS is not Windows acceptance.
- [ ] Separate review PR with honest limitations; no automatic merge/release.

## Native follow-up

Initial repair head `8500a4ed4ca1bde4ea4a7e3b01fc377544bcf4ab` completed
[run 39885569185](https://github.com/XuebinMa/agent-guard/actions/runs/39885569185)
with 21 success / one failure. **All 70 native Windows Broker tests passed**,
including the unchanged race, actual subprocess contenders and interrupted
reservation. Four later CLI approval-ledger tests failed with access denied.
Their source/SDK code was unchanged by the claim repair.

The existing ledger writer opens append-only, but
[LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
requires generic read or write access. Windows now also requests read access
for that already-readable approval ledger; Unix remains append-only. There is
no unlocked fallback, truncation, changed contention timeout or JSONL protocol.
New prefix/frame/state and Unix `0200` controls protect compatibility; the
Windows job additionally runs the targeted SDK approval tests. All new-head
gates must pass again, not borrow the initial grant-test success.
