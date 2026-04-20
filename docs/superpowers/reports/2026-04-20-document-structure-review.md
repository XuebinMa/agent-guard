# agent-guard Documentation Structure Review

## Executive Summary

This review proposes a stable documentation structure for `agent-guard` after its narrative was refocused around execution control.

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

## Old Narrative Residue Table

This section identifies files that still use the old project narrative.

## Priority Action List

This section groups the recommended cleanup actions by priority.
