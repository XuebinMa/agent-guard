# agent-guard Short-Term Wedge Design

## Metadata

- Date: 2026-04-20
- Author: Codex
- Status: Drafted from approved short-term direction in conversation
- Primary audience: Maintainers implementing the next product wedge
- Work type: Product and engineering design

## Goal

Turn `agent-guard` from a shell-first execution-control story into a narrow but unmistakable side-effect execution wedge that still feels coherent in one demo and one API shape.

The short-term ship target is:

- keep shell / terminal as the strongest proof point
- add file write
- add outbound mutation HTTP
- avoid expanding into broad generic capability coverage
- expose one normalized runtime decision surface:
  - `execute`
  - `deny`
  - `ask_for_approval`
  - `handoff`
- ship at least one end-to-end demo that crosses two or more side-effect types

## Assumptions

These assumptions are intentionally explicit so implementation can start without another analysis loop:

1. Short-term means one wedge release, not a control-plane refactor.
2. Node remains the primary demo and fastest adoption path.
3. Rust SDK remains the source of truth for policy evaluation and owned execution behavior.
4. Python parity is not a release blocker for this wedge.
5. Backward compatibility matters enough that existing `check()` / `execute()` APIs should remain available while the new runtime decision surface is introduced additively.

## Scope

### In scope

- Shell / terminal actions
- File write actions
- Outbound mutation HTTP actions
- One normalized decision model across those actions
- Capability-specific audit records and demo flows
- A Node-first end-to-end demo across multiple side effects

### Out of scope

- Read capability redesign
- Email send
- Session-level planner intelligence
- Generic capability expansion beyond the three target side effects
- Full policy workflow, signed approvals, rollback, or replay
- Language-parity-driven work that delays the wedge

## Product Decision

The project should stop using `allow` as the lead runtime concept for the new wedge.

Short-term runtime outcomes should be:

1. `execute`
   - `agent-guard` owns the execution path for the action
2. `handoff`
   - the action is approved, but the host or adapter remains responsible for execution
3. `deny`
   - the action is blocked
4. `ask_for_approval`
   - the action is paused pending explicit approval

This keeps the current shell takeover story, but makes the broader side-effect story legible:

- shell can often be `execute`
- file write can be `execute` when the SDK owns it, or `handoff` where host integration is still preferred
- outbound mutation HTTP can follow the same contract without pretending that every side effect needs the same sandbox backend

## Engineering Shape

### 1. Add a normalized action model

Keep `Tool` compatibility for current callers, but add a more explicit runtime-layer model that can represent:

- action kind
- capability-specific payload
- execution intent
- normalized audit metadata

This action model should be narrow and concrete, not a generic capability framework.

### 2. Add a new runtime decision API instead of breaking the current one

Introduce an additive public API in the Rust SDK and Node binding:

- `decide(...) -> RuntimeDecision`
- `run(...) -> RuntimeOutcome`

Existing `check()` and `execute()` remain as compatibility surfaces and can internally adapt to the new model where practical.

This avoids a wedge release that is blocked on a breaking rename from `Allow` to `Handoff`.

### 3. Make owned execution capability-specific

Short-term owned execution should be intentionally uneven but coherent:

- shell: keep current SDK-owned execution path
- file write: add SDK-owned write execution for a narrow safe write surface
- outbound mutation HTTP: add SDK-owned mutation execution for a narrow request surface

The commonality is not "same sandbox everywhere." The commonality is "same decision boundary before the side effect becomes real."

## Capability Boundaries

### Shell / terminal

- Preserve current Bash-first enforcement path
- Re-express its outcomes through the new runtime decision terminology
- Keep sandbox-backed execution where available

### File write

Short-term file write support should stay narrow:

- operations: create, overwrite, append
- payload: path, content, optional encoding, optional overwrite mode
- policy focus: allowed paths, denied paths, size limit, trust mode

Explicitly exclude:

- delete
- rename / move
- chmod / ownership changes
- recursive directory mutation

### Outbound mutation HTTP

Short-term HTTP support should be explicitly mutation-only:

- allowed methods: `POST`, `PUT`, `PATCH`, `DELETE`
- payload: method, url, optional headers, optional body
- policy focus: destination host, path, method, body size, trust mode

Explicitly exclude:

- browser automation
- cookies / session replay
- arbitrary streaming
- long-lived connections
- generic web-fetch platform scope

## Demo Direction

The wedge demo should be Node-first and cross at least two side effects. The recommended flow is a three-step chain:

1. shell command gathers or formats local project state
2. file write persists an agent-produced artifact into the workspace
3. outbound mutation HTTP attempts to publish or notify via a local mock endpoint

Recommended user-visible behavior:

- safe shell step: `execute`
- safe workspace write: `execute`
- risky external mutation: `ask_for_approval` or `deny`

This demo is better than a single-capability proof because it shows `agent-guard` controlling a sequence of real side effects with one vocabulary.

## Release Shape

### Must ship in the wedge

- normalized runtime decision API
- shell + file write + outbound mutation HTTP support
- one cross-side-effect Node demo
- docs and messaging rewritten around side-effect execution control

### Nice to have if cheap

- Python binding exposure of the new decision terms
- a second demo focused on approval flow
- richer audit rendering for multi-step action chains

## Acceptance Criteria

The short-term wedge is successful when all of the following are true:

1. The README and package docs describe `agent-guard` as side-effect execution control, not a broad platform.
2. A developer can point to one public API that yields `execute`, `deny`, `ask_for_approval`, or `handoff`.
3. File write and outbound mutation HTTP are both real supported surfaces, not just future placeholders.
4. The Node demo shows one agent flow spanning multiple side effects with visibly different decisions.
5. The implementation remains intentionally narrow and does not drift into generic capability sprawl.
