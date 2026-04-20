# Growth & Adoption Plan

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Active Execution Plan |
| **Audience** | Maintainers, Product, DevRel |
| **Version** | 1.0 |
| **Last Updated** | 2026-04-14 |

---

This is a maintainer-facing planning document. It is not the primary product overview and should not be treated as the first entry point for new developers.

## 1. Goal

Increase meaningful usage of `agent-guard` by making the execution-control wedge easier to understand, easier to try, and easier to verify.

This plan optimizes for:

- more developers reaching a successful first run
- more developers understanding the product value in under 60 seconds
- more real integrations with shell or tool-calling agents
- more repeatable proof that `agent-guard` reduces tool-call risk

---

## 2. Core Diagnosis

The project already has substantial technical depth, but adoption is constrained by four communication problems:

1. The primary pain point is not expressed sharply enough.
2. The project currently presents too many capabilities at once.
3. New users do not reach a first success quickly enough.
4. There are not yet enough public “before vs after” proof artifacts.

In practice, many visitors likely leave without answering:

- what exact problem does this solve for me?
- who should use it first?
- how do I try it in 5 minutes?
- what real attack or failure does it stop?

---

## 3. Positioning

### Primary Product Statement

`agent-guard` is an execution control layer for agent side effects. It gives AI application and agent developers a real decision boundary before shell commands and other risky actions become real.

### Secondary Supporting Statement

It helps teams move from “we hope the model behaves” to “the execution boundary decides what actually runs.”

### What It Is Not

- not a general-purpose agent framework
- not a prompt-engineering library
- not a replacement for app-level authorization
- not a full cloud control plane today

---

## 4. Target Users

### ICP 1: AI engineers building code agents or shell-enabled agents

Why they matter:

- highest pain
- easiest demo value
- strongest fit with current product strength

Primary problem:

- “My agent can call shell or file tools, and I need a safety boundary before it touches the host.”

### ICP 2: AI infra teams building tool gateways

Why they matter:

- care about consistent enforcement
- need auditability and policy control

Primary problem:

- “I need a reusable execution-control layer in front of tool execution across teams or products.”

### ICP 3: Security/platform teams reviewing agent deployments

Why they matter:

- high verification sensitivity
- care about receipts, logs, parity, and diagnostics

Primary problem:

- “How do we prove an agent tool call was policy-compliant and sandboxed?”

---

## 5. Value Messages By Audience

### For code-agent builders

- Put a real decision boundary in front of shell tools before the model reaches the OS.
- Add security to LangChain/OpenAI-style tools without rewriting your app.
- Start with `check`, move sensitive tools to `enforce`.

### For infra teams

- Centralize policy decisions at the tool boundary.
- Make enforcement behavior auditable and consistent.
- Keep framework-specific integration thin and reusable.

### For security reviewers

- Generate signed receipts for execution proof.
- Surface real sandbox availability instead of overstating protection.
- Create a paper trail for blocked and approved actions.

---

## 6. Wedge Strategy

The project should not try to win adoption by marketing every capability equally.

### Chosen Wedge

**Shell and high-risk tool-call protection for agent developers**

Why this wedge:

- sharp pain point
- easy to explain
- high perceived risk
- strong demo effect
- aligned with current implementation strength

Everything else should support this wedge, not compete with it.

---

## 7. Adoption Funnel

### Stage A: Awareness

User sees:

- a one-sentence value proposition
- a dangerous command being blocked
- clear framework fit

Primary assets:

- README hero
- short terminal demo
- “without guard vs with guard” comparison

### Stage B: First Success

User runs:

- one quickstart command
- one demo that allows a safe command
- one demo that blocks a risky command

Primary assets:

- Node quickstart
- package-level demo scripts
- 5-minute install instructions

### Stage C: Verification

User verifies:

- real framework compatibility
- platform behavior transparency
- signed receipts / auditability

Primary assets:

- framework runtime tests
- transparency demo
- doctor report
- `guard-verify`

### Stage D: Adoption

User integrates:

- shell tool
- one API tool
- one production policy

Primary assets:

- focused integration guides
- examples by framework
- migration guidance: `check` to `enforce`

---

## 8. Execution Phases

## Phase 1: Message Clarity

Goal:

- make first-contact understanding dramatically better

Deliverables:

- rewrite root README hero and first screen
- add “Who is this for?” and “Why now?” framing
- make 5-minute quickstart prominent
- replace stale status signals and misleading phase shorthand

Success metric:

- a new visitor can explain the product in one sentence after reading the first screen

## Phase 2: First-Run Experience

Goal:

- make a successful first run almost effortless

Deliverables:

- stable Node quickstart
- command-copyable examples
- “allowed vs blocked” demo output in docs
- framework-specific getting-started pages

Success metric:

- a new user can run a real demo in under 10 minutes without reading architecture docs first

## Phase 3: Proof & Verification

Goal:

- show that the product works against realistic failure modes

Deliverables:

- attack-path demos
- “prompt injection to shell” walkthrough
- “check vs enforce” decision table
- receipt verification walkthrough

Success metric:

- public artifacts clearly demonstrate blocked risky actions and explain why

## Phase 4: Distribution

Goal:

- put the project in front of the right early users

Deliverables:

- publish focused examples for LangChain/OpenAI-style tool integrations
- create 2-3 technical blog posts
- share short demo clips
- outreach to code-agent / tool-runtime builders

Success metric:

- first external integrations, issues, and usage feedback from target ICPs

## Phase 5: Conversion to Ongoing Adoption

Goal:

- turn curiosity into repeated use

Deliverables:

- compatibility matrix
- versioned examples
- clearer production deployment guidance
- policy starter packs

Success metric:

- users move from demo use to one real protected tool in development or staging

---

## 9. Concrete Work Queue

### Must Do First

1. Rewrite root README for sharper positioning.
2. Promote Node quickstart and blocked-command demo.
3. Add a “Who should use this?” section.
4. Add a “before vs after” explanation near the top.

### Should Do Next

1. Publish a dedicated shell-tool safety guide.
2. Add a ChatGPT Custom GPT / Actions example architecture doc.
3. Document `check` vs `enforce` by use case.
4. Add a support matrix for Node and Python adapters.

### Then Do

1. Create attack demo recordings.
2. Create case-study style examples.
3. Package more policy templates for common teams.

---

## 10. Metrics

Track these as the project evolves:

- README-to-quickstart completion rate
- number of demo runs or example forks
- issues/discussions from first-time integrators
- stars from target-user repos or communities
- framework-specific adoption questions
- external references to the shell-tool protection use case

---

## 11. Current Implementation Status

### Completed in this round

- Node high-level adapter layer
- real LangChain/OpenAI runtime validation
- Node quickstart that demonstrates allowed vs blocked behavior
- three-minute proof onboarding path
- launch kit and shell-agent case study for reusable outreach

### Immediate Next Implementation Step

Rewrite the root README so the strongest wedge is visible on the first screen.

### Recommended Next Step After That

Add a dedicated “secure shell tools” guide and a ChatGPT Actions integration walkthrough.
