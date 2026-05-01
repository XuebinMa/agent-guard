# Superpowers — Maintainer Workflow Artifacts

This directory holds the working artifacts produced by the multi-agent maintainer workflow used inside the `agent-guard` repository. Files here are **not** authoritative documentation; they are the trace of how a particular change was researched, planned, and reviewed. Authoritative reference material lives under [`docs/concepts/`](../concepts/), [`docs/guides/`](../guides/), and [`docs/reference/`](../reference/).

## Lifecycle

A change moves through three artifact stages. Each stage lives in its own subdirectory and is dated `YYYY-MM-DD-<slug>.md`:

| Stage | Directory | Purpose | Lifetime |
| :--- | :--- | :--- | :--- |
| 1. Spec | [`specs/`](specs/) | Design notes — assumptions, options considered, trade-offs, the chosen approach. Written **before** implementation. | Frozen once the spec is accepted. Kept indefinitely as historical context. |
| 2. Plan | [`plans/`](plans/) | Implementation plan — file-level breakdown, task ordering, test strategy. Derived from the spec. | Updated during implementation; archived once the change is merged. |
| 3. Report | [`reports/`](reports/) | Post-merge retrospective — what actually shipped, what changed during implementation vs the plan, follow-ups. | Written once the PR lands. Read-mostly afterwards. |

Not every change uses all three stages. Small fixes typically skip the spec; routine maintenance may skip both spec and plan. The directories carry whatever was actually produced.

## When to file something here

File a `specs/` doc when:
- The change introduces or rewrites a public API.
- Multiple reasonable approaches exist and the choice is non-obvious.
- The change touches security or correctness boundaries (sandbox, policy evaluation, audit).
- Cross-language parity is at stake.

File a `plans/` doc when:
- The change spans more than one or two PRs.
- Multiple agents or contributors will work in parallel and need a shared map.

File a `reports/` doc when:
- The plan deviated meaningfully from what shipped — record the deviation so future readers do not have to re-derive it.
- The change surfaced a follow-up that should be tracked but is out of scope for the original PR.

## Status of files in this tree

The dated files are pinned to the date the artifact was written, not the date of merge. To see what shipped, read the corresponding PR or `git log`. To see what's currently in production, read [`docs/concepts/`](../concepts/) and [`docs/reference/`](../reference/).

If you're a maintainer adding a new artifact, follow the existing naming convention and link forward/backward between the three stages where they exist.
