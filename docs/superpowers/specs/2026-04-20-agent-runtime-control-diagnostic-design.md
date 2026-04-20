# agent-guard Diagnostic Design

## Metadata

- Date: 2026-04-20
- Author: Codex
- Status: Approved in conversation, written for review
- Primary audience: Maintainers and product direction owners
- Primary target user: AI application and agent developers
- Report type: Project diagnostic report

## Goal

Produce a diagnostic report that answers four questions for `agent-guard`:

1. What real user need does the project currently serve?
2. Where does that need differ from real-world market demand?
3. What are the project's main weaknesses today?
4. What direction gives the project the best chance to stand out and gain adoption?

The report is not a code review and not a broad market landscape deck. It is a focused product-and-strategy diagnostic for an existing project.

## Scope

### In scope

- The current product definition implied by the repository, docs, and demos
- The gap between current project positioning and real-world developer demand
- Comparison against both direct competitors and real substitute solutions
- Short-, medium-, and long-term improvement directions
- A recommended sharper product wedge and positioning statement

### Out of scope

- Detailed implementation tasks
- File-by-file technical refactors
- Pricing or business model design
- Enterprise sales process design
- Full competitor catalog

## Analysis Frame

The report evaluates `agent-guard` through four lenses:

1. Problem strength
   - Is the problem common and painful enough for developers to adopt a new control layer?
2. Adoption friction
   - How much mental, operational, and integration cost does adoption require?
3. Substitute pressure
   - What are developers already using instead, and why might those options win?
4. Positioning clarity
   - Is the project's identity crisp enough that users can quickly understand why it exists?

## Evidence Sources

### Internal evidence

- Repository README and package READMEs
- Architecture and support matrix docs
- Threat model and adapter contract
- Current demos and onboarding flows
- Recent commits that clarify shell-first enforcement and trust tooling

### External evidence

- Framework-layer realities such as OpenAI Agents and LangChain guardrails and approvals
- Standardization trends such as MCP becoming a wider ecosystem layer
- Infrastructure substitutes such as sandbox and isolated compute products
- The practical fact that developers often choose lighter middleware or heavier sandbox infrastructure before adopting a new middle layer

## Core Diagnostic Thesis

`agent-guard` should not currently be described as a complete control plane. The strongest current wedge is narrower and more concrete:

`agent-guard` is an execution control layer between agent tool intent and real-world side effects.

Its current strongest proof point is shell-first enforcement, but its future growth path should be framed around side-effect execution control rather than around a generic "AI security platform" identity.

## Current Need Definition

The current real need served by the project is:

`Give tool-calling AI applications a control layer that sits in front of risky execution, especially shell and other high-risk side effects, so that dangerous actions can be denied, escalated, sandboxed, and audited before they become real.`

This need is real, but the repository currently presents a wider identity than the most mature product surface actually supports.

## Real-World Gap Assessment

The report will explicitly argue that the strategic direction is valid, but the timing and packaging matter.

### Gap 1: Developers buy a wedge, not a full control plane

Real-world developers usually adopt either:

- light framework-level controls such as guardrails, approvals, and middleware, or
- heavy infrastructure-level controls such as isolated sandboxes or remote execution environments

They do not usually buy an abstract "control plane" first. They buy a narrowly defined, immediately useful execution boundary.

### Gap 2: The three proposed upgrades are not equally immediate

The report will assess the three candidate upgrades as follows:

1. Session- and plan-level decisioning
   - Strategically important, but too upstream and framework-dependent to lead the current wedge
2. Generic capability enforce
   - The strongest medium-term pull because it expands beyond shell into real side-effect control
3. Policy workflow
   - Essential for enterprise control planes, but better treated as a later amplifier than as the first adoption hook

### Gap 3: The project sits between two stronger narratives

The market is already shaped by:

- framework-native safety and approval layers on the top, and
- infrastructure-native sandbox and isolated runtime products on the bottom

If `agent-guard` tries to sound like both, it becomes blurred. The report will recommend defining the project as a middle-layer execution controller that understands side effects at the agent action boundary.

## Main Weaknesses To Highlight

The diagnostic report will call out five main weaknesses:

1. Product identity is too broad
2. The strongest enforcement story is still over-concentrated on shell
3. The project overlaps with strong players above and below it without sharply naming its unique middle layer
4. Adoption value is still not immediate enough for many developers
5. The abstractions required for a future control plane are not yet explicit enough

## Positioning Recommendation

The report will recommend that the project stop leading with a broad platform identity and instead lead with:

`agent side-effect execution control`

That framing should distinguish it from:

- framework orchestration and guardrails
- raw sandbox or compute isolation products
- generic logging or trust tooling

The product claim should be:

`When an agent is about to cause a real-world side effect, agent-guard can stop it before execution, route it for approval, or take over the execution path.`

## Keep, Weaken, Drop

The report will include a concrete strategic triage:

### Keep and strengthen

- Pre-execution policy decisioning
- Shell-first enforcement
- Audit and proof as trust support
- Node-first adoption surface
- Approval, deny, and takeover semantics

### Keep but weaken in the narrative

- Cross-framework breadth
- OS sandbox implementation detail
- Doctor and capability transparency utilities
- Receipt signing as a standalone feature

### Stop leading with for now

- Full control plane identity
- Broad "all capabilities" language
- Enterprise workflow as the phase-one value proposition
- Language parity as a front-page message

## Roadmap Recommendation

### Short term: 1-3 months

- Rewrite the project narrative around side-effect execution control
- Reframe external language from `tool` and `payload` toward `action`, `side effect`, and `execution control outcome`
- Create a single unmistakable wedge demo around high-risk side effects
- Publicly focus on a very small set of capability verticals
- Demote trust tooling from lead value proposition to supporting proof layer

### Medium term: 6-12 months

- Introduce an explicit capability operation model
- Upgrade ask/deny semantics into resumable approval and takeover flows
- Build deeper capability-specific control for a few high-value side effects
- Add session-scoped risk correlation without overreaching into grand planner intelligence

### Long term: 1-2 years

- Productize policy workflow: signed approval, promotion, rollback, replay
- Expand session- and plan-level runtime intelligence
- Build a real control plane layer on top of a proven execution control foundation

## Recommended Capability Focus

Do not pursue abstract generic enforcement everywhere at once. The report should recommend a narrow first batch:

- shell / terminal
- file write
- outbound mutation HTTP
- optional fourth: email send

These are frequent, risky, and legible enough to form a strong developer wedge.

## Final Strategic Conclusion

The central conclusion of the diagnostic report will be:

`agent-guard` should stop trying to sound like a broad AI security platform and instead become the clearest execution control layer for agent side effects.

That means:

- tighter identity
- fewer lead messages
- a stronger wedge
- capability-specific control before generic sprawl
- control plane ambitions deferred until the execution control layer is clearly won

## Expected Deliverable Structure

The final report should use this structure:

1. Current implied demand and target user
2. Real-world demand and market substitutes
3. Gaps between current project shape and real adoption needs
4. Main weaknesses in current positioning and product definition
5. Recommended sharper middle-layer wedge
6. Keep / weaken / drop strategic choices
7. Short-, medium-, and long-term directions
8. Final recommendation and project identity statement

## Decisions Made During Brainstorming

- The report serves AI application and agent developers first
- The report is a project diagnostic, not a pure technology audit
- Both direct competitors and substitute solutions matter
- Recommendations should be layered across short, medium, and long time horizons
- Developer adoption comes before enterprise control-plane positioning
- The project should seek a sharper middle-layer wedge rather than attempting to compete head-on with both frameworks and infrastructure products
