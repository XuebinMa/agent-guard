# agent-guard Documentation Structure Review

## Executive Summary

The main problem is a combination of structure drift and old narrative residue, with some duplication in supporting material rather than one dominant duplicate-heavy failure mode. The active path is currently too wide, because historical, strategy, and support docs still sit too close to newcomer-facing entry points. The next cleanup should focus on P0 first so the developer path reflects the current execution-control story before secondary reorganization work begins.

## Review Scope

This review covers tracked files under `docs/` plus tracked crate-level `README.md` files that act as developer-facing documentation.

Tracked file discovery command used for this review:

    git ls-files 'docs/**' 'crates/**/README.md' | sort

Review exclusions:

- untracked local process files
- generated cache files such as `crates/agent-guard-python/.pytest_cache/README.md`
- non-documentation scripts unless they are directly part of a tracked documentation surface

## Target Structure Summary

The documentation set should be evaluated against six stable layers:

### 1. Top-level entry points

Role:

- define what the project is
- route new users to the next step
- keep the current narrative crisp

Expected files:

- `README.md`
- `docs/README.md`

### 2. Getting Started

Role:

- help a developer reach time-to-first-understanding and time-to-first-success quickly

Expected files:

- quick proof guides
- quickstarts
- first integration guides
- mode-selection guides

### 3. Integration / Reference

Role:

- help users choose an integration path and consult decision/reference material once they are integrating more seriously

Expected files:

- support matrices
- adapter contracts
- capability references
- package READMEs used as integration docs

### 4. Operations / Security

Role:

- support operators, security reviewers, and maintainers dealing with real deployment boundaries

Expected files:

- threat model
- deployment
- observability
- security audit
- platform sandbox docs

### 5. Adoption / Messaging

Role:

- hold reusable public-facing explanation assets without crowding the product entry path

Expected files:

- launch kit
- case studies
- release announcement drafts
- FAQ
- social and external channel packs

### 6. Archive / Internal Process

Role:

- retain archived product and history material, plus internal process artifacts, without presenting them as active product guidance

Expected files:

- phase documents
- archived release artifacts
- superseded reports
- superpowers plans and process files

In the file mapping table below, `keep` means the file can remain in the active structure, `merge` means it overlaps with another file enough to justify later consolidation, `move down` means it should remain available but at lower prominence, `archive` means it should leave the active path while staying accessible, and `delete candidate` means its value appears weak enough that later removal should be considered.

## File Mapping Table

This section maps reviewed files to recommended structure layers and actions.

| Path | Current role | Recommended layer | Action | Reason |
| :--- | :--- | :--- | :--- | :--- |
| `README.md` | Primary repository entry point and project definition | Top-level entry points | keep | It already sets the current execution-control narrative and routes new users to the proof path. |
| `docs/README.md` | Documentation hub and route map | Top-level entry points | keep | It has a clear hub role and should remain the main directory-level navigator. |
| `docs/architecture-and-vision.md` | Strategic roadmap and architecture context | Archive / Internal Process | archive | It is primarily a future-facing strategy artifact, so it should remain accessible without presenting it as active user-facing reference. |
| `docs/growth-and-adoption-plan.md` | Internal adoption and messaging plan | Archive / Internal Process | archive | It is a maintainer-facing execution plan rather than active product documentation. |
| `docs/release-notes-v0.2.0.md` | Historical prerelease notes | Archive / Internal Process | archive | It should stay accessible as release history without competing with current entry docs. |
| `docs/guides/getting-started/attack-demo-playbook.md` | Demo script and proof support asset | Adoption / Messaging | move down | It is mainly a demo and storytelling asset for evaluators and maintainers, while the core newcomer path is better served by the proof guide itself. |
| `docs/guides/getting-started/chatgpt-actions.md` | Specific ChatGPT Actions integration guide | Integration / Reference | move down | It is a valid integration path, but too specific to sit in the core getting-started lane. |
| `docs/guides/getting-started/check-vs-enforce.md` | Core mode-selection guide | Getting Started | keep | Choosing the right execution mode is part of the first real integration decision. |
| `docs/guides/getting-started/migration-guide.md` | Hardening and sandbox transition guide | Operations / Security | move down | It becomes most relevant after initial adoption, when teams are tightening deployment posture. |
| `docs/guides/getting-started/secure-shell-tools.md` | Shell-first integration guide for the strongest current use case | Getting Started | keep | It matches the current adoption wedge and belongs in the active first-success path. |
| `docs/guides/getting-started/three-minute-proof.md` | Fast evaluation and proof demo | Getting Started | keep | It is the clearest time-to-value entry point for new users. |
| `docs/guides/getting-started/trust-tooling.md` | Policy signing, receipts, and doctor workflow guide | Operations / Security | move down | It is valuable, but advanced trust workflow should not crowd first-run onboarding. |
| `docs/guides/getting-started/user-manual.md` | Broad installation and integration guide | Getting Started | keep | It remains the main longer-form onboarding document after the quick proof. |
| `docs/adapter-contract.md` | Cross-binding integration contract for maintainers | Integration / Reference | keep | It has a clear reference role for adapters and binding consistency. |
| `docs/capability-parity.md` | Platform enforcement boundary matrix | Integration / Reference | keep | It functions as a capability reference and comparison matrix, so it fits the reference layer even though it documents security boundaries. |
| `docs/framework-support-matrix.md` | Integration surface and readiness chooser | Integration / Reference | keep | It directly helps developers choose the right supported path. |
| `docs/m3.1-support-matrix.md` | Milestone-specific design note for context-aware rules | Archive / Internal Process | archive | The milestone framing makes it read as historical design residue rather than active user-facing structure. |
| `docs/node-adapter-gap-report.md` | Node readiness audit and gap report | Archive / Internal Process | archive | It is an implementation audit that is largely superseded by active package and support docs. |
| `crates/agent-guard-node/README.md` | Package-level Node integration guide | Integration / Reference | keep | It is a primary package entry point for a mature integration surface. |
| `crates/agent-guard-python/README.md` | Package-level Python integration guide | Integration / Reference | keep | It serves as the package entry point for Python users and belongs with the active integration documentation. |
| `docs/guides/operations/deployment-guide.md` | Production deployment and hardening guide | Operations / Security | keep | It is a direct operator-facing deployment document and belongs in the active operations layer. |
| `docs/guides/operations/observability.md` | Monitoring, audit, and telemetry operations guide | Operations / Security | keep | It supports real deployment monitoring and should remain part of the active operational documentation. |
| `docs/research-appcontainer.md` | Windows AppContainer feasibility spike and research record | Archive / Internal Process | archive | It reads as completed implementation research rather than ongoing operator guidance. |
| `docs/sandbox-linux.md` | Linux sandbox behavior and enforcement boundary reference | Operations / Security | keep | It documents the current Linux runtime boundary and is useful for deployers and security reviewers. |
| `docs/sandbox-macos.md` | macOS sandbox limitations and usage reference | Operations / Security | keep | It clearly documents the active macOS prototype boundary and should stay available for platform-specific review. |
| `docs/sandbox-windows.md` | Windows sandbox limitations and usage reference | Operations / Security | keep | It explains the current Windows execution boundary and belongs with the active platform security docs. |
| `docs/security-audit.md` | Release-era security audit and remediation summary | Operations / Security | move down | It should be retained as a useful release checkpoint, but it is more time-bound than the evergreen threat model and should not anchor the active security narrative. |
| `docs/threat-model.md` | Primary threat and attack-surface reference | Operations / Security | keep | It is the clearest top-level security posture document and should remain active. |
| `docs/guides/adoption/case-study-shell-agent.md` | Problem-to-value case study for the shell-first wedge | Adoption / Messaging | keep | It helps evaluators recognize the strongest current use case without crowding core onboarding. |
| `docs/guides/adoption/demo-asset-workflow.md` | Maintainer workflow for producing consistent demo visuals and clips | Archive / Internal Process | move down | It is primarily an internal production workflow for maintainers, so it should stay available without reading like a primary outward-facing adoption document. |
| `docs/guides/adoption/discussions-announcement.md` | Channel-specific GitHub Discussions launch draft | Adoption / Messaging | move down | It is useful as a launch asset, but it is narrower and more time-bound than the main adoption docs. |
| `docs/guides/adoption/external-channel-post-pack.md` | Multi-channel launch posting pack | Adoption / Messaging | move down | It is a useful outbound bundle, but its first-wave launch focus makes it less evergreen than the core messaging assets. |
| `docs/guides/adoption/faq-for-new-users.md` | First-wave FAQ for evaluators and new users | Adoption / Messaging | keep | It directly supports adoption questions that arise after a first post, demo, or release note. |
| `docs/guides/adoption/launch-kit.md` | Central messaging and demo guidance for maintainers | Adoption / Messaging | keep | It functions as the main reusable adoption hub and fits the target structure well. |
| `docs/guides/adoption/release-announcement.md` | Reusable public release announcement draft | Adoption / Messaging | move down | It should remain available, but it is a campaign asset rather than a primary long-lived doc hub. |
| `docs/guides/adoption/social-posts.md` | Reusable social and community post templates | Adoption / Messaging | keep | It is an evergreen messaging asset that belongs in the adoption layer. |
| `docs/archive/README.md` | Index and explanation for archived documentation | Archive / Internal Process | keep | It is the right archive entry point and should remain the navigator for historical material. |
| `docs/archive/phase2-design.md` | Historical implementation summary for Phase 2 work | Archive / Internal Process | keep | It is clearly historical project history and already belongs in the archive layer. |
| `docs/archive/phase2-done.md` | Historical completion checklist for Phase 2 | Archive / Internal Process | keep | It has value as implementation history and is already appropriately placed as archive material. |
| `docs/archive/phase3-design.md` | Historical design document for Phase 3 expansion | Archive / Internal Process | keep | It is archived milestone design material rather than active product guidance. |
| `docs/archive/phase6-design.md` | Historical enterprise-security roadmap design | Archive / Internal Process | keep | It is roadmap history that should stay available without being treated as current user documentation. |
| `docs/archive/phase8-design.md` | Historical future-phase design for deeper isolation work | Archive / Internal Process | keep | It is clearly a forward-looking historical design artifact and already sits in the right layer. |
| `docs/archive/release-notes-v0.1.0.md` | Archived release notes for an older release line | Archive / Internal Process | keep | It serves as retained release history and already belongs in archive. |
| `docs/archive/sales-demo-script.md` | Historical enterprise sales and demo script | Archive / Internal Process | keep | It is a legacy messaging artifact that is better preserved as history than surfaced as active guidance. |
| `docs/superpowers/specs/2026-04-20-agent-runtime-control-diagnostic-design.md` | Internal process spec for the product diagnostic report | Archive / Internal Process | keep | It is an internal design artifact and fits the process-material portion of the archive layer. |
| `docs/superpowers/specs/2026-04-20-document-structure-and-cleanup-design.md` | Internal process spec for the documentation structure review | Archive / Internal Process | keep | It is a process document for maintainers and belongs with internal planning artifacts rather than product docs. |

## Old Narrative Residue Table

This section identifies files that still use the old project narrative.

| Path | Old narrative type | Current layer or prominence | Severity | Reason |
| :--- | :--- | :--- | :--- | :--- |
| `docs/README.md` | broad AI security platform framing | Top-level docs hub and first-stop entry path after the repository README | high | The opening sentence still describes `agent-guard` as a high-performance security layer for AI Agents, which is broader than the current execution-control wedge. |
| `docs/architecture-and-vision.md` | full control plane framing too early | Visible docs-root roadmap document linked from the documentation hub | high | It presents `agent-guard` as an Agent Security Runtime, foregrounds ecosystem and trust phases, and still advertises a Phase 3 control plane roadmap in a current-looking doc. |
| `docs/growth-and-adoption-plan.md` | ecosystem / trust presented as the main front-page hook | Active docs-root adoption and messaging plan | high | The ICP, funnel, and proof sections still lean on reusable security layer, trust, and cross-team platform language more than the shell-first execution-control proof point. |
| `docs/release-notes-v0.2.0.md` | broad AI security platform framing | Historical release notes that still sit in the active docs root | medium | The overview now names shell-first enforcement, but the feature framing still sells enterprise observability, SIEM, and provenance as part of a broader platform identity. |
| `crates/agent-guard-python/README.md` | shell-first not framed as the current proof point | Package README and primary Python user entry path | high | The intro and feature list position the package as a generic Python security execution runtime for AI agents instead of leading with shell-first execution control as the strongest current proof. |
| `docs/archive/phase2-design.md` | shell-first not framed as the current proof point | Archived phase design document | low | It prioritizes Python binding and LangChain integration as the main adoption unlock, which reflects a pre-wedge story rather than the current shell-first execution-control proof point. |
| `docs/archive/phase2-done.md` | shell-first not framed as the current proof point | Archived completion checklist | low | The checklist is organized around Python binding and ecosystem demos instead of presenting shell-first execution control as the strongest current proof. |
| `docs/archive/phase6-design.md` | broad AI security platform framing | Archived enterprise roadmap design | low | It centers an enterprise-grade security layer with receipts, SIEM, and capability modeling, which reflects the wider platform narrative rather than today's narrower proof point. |
| `docs/archive/phase8-design.md` | broad AI security platform framing | Archived future-phase trust roadmap | low | The roadmap is built around policy signing, execution proofs, hardware root of trust, and SIEM-style expansion rather than a shell-first execution-control story. |
| `docs/archive/sales-demo-script.md` | broad AI security platform framing | Archived sales and demo narrative asset | low | It leads with zero-trust, signed receipts, compliance, and enterprise-ready messaging, so it captures the broader platform pitch clearly even though it is historical. |

## Priority Action List

### P0: Resolve active-path confusion

- identify overlapping entry-point docs
- identify high-severity old-narrative files on the developer path
- identify files whose current prominence no longer matches their role

### P1: Reorganize supporting material

- move supporting but secondary docs down from the main path
- identify merge candidates among support matrices, strategy docs, and package-level references
- separate integration references from adoption assets more clearly

### P2: Tidy historical and process material

- identify archive candidates that should leave the active path
- identify process-oriented `docs/superpowers/` material that should remain internal
- identify low-value duplicate artifacts that may become delete candidates later
