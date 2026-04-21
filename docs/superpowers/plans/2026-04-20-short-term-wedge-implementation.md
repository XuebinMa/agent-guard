# Short-Term Wedge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a narrow but unmistakable short-term wedge for `agent-guard` that keeps shell strong, adds file write and outbound mutation HTTP, exposes one normalized runtime decision API, and lands one multi-side-effect demo.

**Architecture:** Add a new runtime-layer action and decision model without breaking the existing shell-first API surface. Implement owned execution for shell, file write, and outbound mutation HTTP in the Rust SDK, expose the new decisions through the Node binding and adapters, then land a Node-first demo and documentation refresh around the side-effect execution-control narrative.

**Tech Stack:** Rust, Node.js, N-API, `reqwest`, filesystem APIs, Markdown, `httpmock`

---

## Outcome Definition

This plan is complete when the repository has all of the following:

- one additive runtime decision API with outcomes `execute`, `deny`, `ask_for_approval`, and `handoff`
- shell / terminal remains fully supported
- file write is supported as a narrow owned-execution capability
- outbound mutation HTTP is supported as a narrow owned-execution capability
- at least one Node demo crosses two or more side effects end-to-end
- public docs lead with side-effect execution control instead of broad platform framing

## Scope Guardrails

### Must do

- shell / terminal
- file write
- outbound mutation HTTP
- Node-first demo
- additive API migration path

### Must not do

- generic capability framework expansion
- email send in this release
- session or plan intelligence
- full approval workflow productization
- Python parity work that blocks the wedge

## File Structure

### Core runtime contract

- Modify: `crates/agent-guard-core/src/types.rs`
- Modify: `crates/agent-guard-core/src/decision.rs`
- Modify: `crates/agent-guard-core/src/payload.rs`
- Modify: `crates/agent-guard-core/src/policy.rs`
- Modify: `crates/agent-guard-core/src/lib.rs`
- Modify: `crates/agent-guard-core/src/tests.rs`

### SDK runtime and execution

- Modify: `crates/agent-guard-sdk/src/guard.rs`
- Modify: `crates/agent-guard-sdk/src/lib.rs`
- Create: `crates/agent-guard-sdk/src/runtime.rs`
- Create: `crates/agent-guard-sdk/src/executors.rs`
- Modify: `crates/agent-guard-sdk/tests/integration.rs`
- Modify: `crates/agent-guard-sdk/tests/execute_integration.rs`
- Create: `crates/agent-guard-sdk/tests/runtime_decision_integration.rs`
- Modify: `crates/agent-guard-sdk/examples/quickstart.rs`
- Create: `crates/agent-guard-sdk/examples/side_effect_wedge.rs`

### Node binding, adapters, and demo

- Modify: `crates/agent-guard-node/src/lib.rs`
- Modify: `crates/agent-guard-node/index.d.ts`
- Modify: `crates/agent-guard-node/runtime.d.ts`
- Modify: `crates/agent-guard-node/adapters.js`
- Modify: `crates/agent-guard-node/README.md`
- Modify: `crates/agent-guard-node/test-adapters.js`
- Create: `crates/agent-guard-node/demos/demo_side_effect_wedge.js`

### Top-level docs

- Modify: `README.md`
- Modify: `docs/guides/getting-started/check-vs-enforce.md`
- Modify: `docs/guides/getting-started/three-minute-proof.md`
- Create: `docs/guides/getting-started/side-effect-wedge-demo.md`

## Proposed Execution Order

1. Lock the runtime contract first.
2. Implement file write and outbound mutation HTTP in the SDK.
3. Expose the contract in Node and update the adapters.
4. Land the cross-side-effect demo.
5. Refresh docs and messaging last, once the API and demo are real.

## Workstream 1: Lock The Wedge Contract

### Objective

Define the exact public language and narrow action schema before building more capability code.

### Deliverables

- additive `RuntimeDecision` and `RuntimeOutcome` types
- narrow action schema for shell, file write, and outbound mutation HTTP
- compatibility story for existing `check()` / `execute()`

### Key decisions

- Keep `GuardDecision` for compatibility
- Add a new runtime vocabulary instead of renaming `allow` in place
- Treat `handoff` as approved-host-exec, distinct from guard-owned `execute`

### Acceptance criteria

- one Rust API can represent `execute`, `deny`, `ask_for_approval`, and `handoff`
- existing callers still compile with no immediate breaking rename
- the new API names are reflected in Node type definitions

### Engineering notes

- `write_file` payload must stop being path-only in practice; it needs content-aware execution input
- `http_request` payload must be upgraded from URL-only extraction to method-plus-URL extraction for mutation policy
- do not add broad generic capability abstractions beyond what these three action kinds need

## Workstream 2: Implement Narrow File Write Execution

### Objective

Make file write a first-class wedge capability without expanding into full filesystem mutation control.

### Supported surface

- create file
- overwrite file
- append file

### Explicit non-goals

- delete
- rename
- chmod
- symlink management
- recursive copy or move

### Deliverables

- normalized file write action payload
- owned execution path in SDK
- audit data for file path, write mode, and content hash or size
- tests for workspace allowlists, path denials, and size limits

### Acceptance criteria

- a trusted workspace write can complete through the new runtime path
- denied paths still stop before mutation
- existing shell behavior is unaffected

## Workstream 3: Implement Outbound Mutation HTTP

### Objective

Add a second non-shell side effect that proves the project is moving toward execution control, not just shell gating.

### Supported surface

- `POST`
- `PUT`
- `PATCH`
- `DELETE`

### Explicit non-goals

- browser or session automation
- full web-fetch platform
- streaming uploads
- cookie jars
- websocket or long-lived connections

### Deliverables

- normalized HTTP mutation action payload
- policy checks against method and destination
- owned execution path in SDK
- tests using a local mock endpoint
- audit data for method, URL, and request body hash

### Acceptance criteria

- a safe allowed mutation request can execute against a local test server
- blocked destinations never send the request
- risky destinations can surface `ask_for_approval`

## Workstream 4: Node Binding And Adapter Upgrade

### Objective

Expose the new runtime wedge where developers are most likely to touch it first.

### Deliverables

- Node binding support for runtime decision and runtime outcome types
- adapter handling for `handoff` versus `execute`
- backward-compatible wrapper behavior for existing `check` / `enforce` / `auto` modes
- one Node demo that crosses multiple side effects

### Decision rules

- `enforce` should map to guard-owned execution when the capability supports it
- `check` should remain the lowest-risk incremental path
- `auto` should prefer the new runtime decision path but must not silently bypass denies or approvals

### Acceptance criteria

- a Node user can see the normalized decision terms in types and runtime errors
- current shell quickstarts still work
- the new multi-side-effect demo runs without custom patching

## Workstream 5: Demo And Narrative Refresh

### Objective

Make the wedge obvious from the outside.

### Demo recommendation

Ship a Node-first demo with this flow:

1. run a shell step to gather or format project data
2. write an artifact into the workspace
3. attempt an outbound mutation HTTP call to a local mock service

Recommended visible outcomes:

- shell step: `execute`
- file write step: `execute`
- risky HTTP mutation: `ask_for_approval` or `deny`

### Documentation updates

- top-level README runtime diagram and wording
- Node README positioning and example code
- getting-started guidance on the new runtime decisions
- a dedicated demo walkthrough doc

### Acceptance criteria

- the demo can be used as the primary wedge proof
- docs consistently use `action`, `side effect`, and `runtime decision` language
- docs stop implying generic broad capability coverage

## Milestones

### Milestone 1: Contract Freeze

Target outcome:

- merged design for runtime decisions and action payloads

Exit criteria:

- types and naming are agreed
- scope guardrails are written down in code comments or docs
- file write and HTTP mutation payload shapes are fixed

### Milestone 2: Runtime Capability Completion

Target outcome:

- shell, file write, and outbound mutation HTTP all work through the runtime layer

Exit criteria:

- integration tests pass for all three capabilities
- Node binding exposes the new decisions
- demo implementation can be built on the real runtime path

### Milestone 3: Wedge Proof

Target outcome:

- docs and demo make the new story immediately legible

Exit criteria:

- one multi-side-effect demo is runnable
- README and Node README reflect the new wedge
- no front-page copy leads with broad platform identity

## Verification Plan

### Core and SDK

Run:

```bash
cargo test -p agent-guard-core
cargo test -p agent-guard-sdk
```

Expected:

- new runtime decision tests pass
- existing shell integration tests remain green
- new file write and HTTP mutation integration tests pass

### Workspace-level confidence pass

Run:

```bash
cargo test --workspace --all-features
```

Expected:

- no regression in existing crates

### Node validation

Run:

```bash
npm test --prefix crates/agent-guard-node
node crates/agent-guard-node/demos/demo_side_effect_wedge.js
```

Expected:

- Node adapter tests pass
- demo prints at least two different side-effect steps with normalized runtime outcomes

## Risks And Controls

### Risk 1: Scope creep into generic capability infrastructure

Control:

- block any abstraction that is not directly needed by shell, file write, or mutation HTTP

### Risk 2: Breaking current adopters through terminology churn

Control:

- add the new runtime API; do not replace `check()` / `execute()` in the same wedge release

### Risk 3: HTTP execution drags the SDK into async redesign

Control:

- keep the short-term implementation narrow and compatible with the existing execution surface
- prefer the simplest owned execution path that satisfies the demo and tests

### Risk 4: Demo becomes too synthetic

Control:

- make the demo cross real side effects with visibly different decisions instead of showing three isolated toy calls

## Recommended Delivery Sequence

### Phase 1

- design and merge the runtime contract
- keep the public scope intentionally narrow

### Phase 2

- implement file write execution
- implement HTTP mutation execution
- land Rust tests first

### Phase 3

- expose the new runtime model in Node
- update adapters and demo

### Phase 4

- refresh docs and positioning
- tighten examples around the wedge proof

## Explicit De-Scopes For This Plan

- no email capability
- no read capability redesign
- no plan/session decisioning
- no approval workflow persistence
- no control-plane product surface
- no Python-blocking parity milestone
