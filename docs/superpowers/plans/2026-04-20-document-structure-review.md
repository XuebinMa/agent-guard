# Documentation Structure Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a versioned documentation structure review report that defines the target doc architecture, maps current files to actions, and isolates old-narrative residue across `docs/` and crate READMEs.

**Architecture:** Write one durable review artifact under `docs/superpowers/reports/` and build it in focused passes. First scaffold the report and lock the review scope to tracked documentation files, then add the target structure summary, then map files by area, then add the old-narrative residue table, and finally add a prioritized cleanup action list with a consistency pass.

**Tech Stack:** Markdown, Bash, `git`, `find`, `rg`

---

## File Structure

- Create: `docs/superpowers/reports/2026-04-20-document-structure-review.md`
  - Final review artifact with target structure, file mapping table, old-narrative residue table, and priority actions
- Reference: `docs/superpowers/specs/2026-04-20-document-structure-and-cleanup-design.md`
  - Approved design for this review
- Reference: `README.md`
  - Current top-level positioning
- Reference: `docs/README.md`
  - Documentation hub and current doc discovery path
- Reference: `crates/agent-guard-node/README.md`
  - Strongest package-level developer-facing path
- Reference: `crates/agent-guard-python/README.md`
  - Secondary package-level integration path

## Scope Check

This plan is appropriately scoped as one review artifact. It does not yet rewrite or move docs. It inventories tracked documentation, not local untracked process files or generated cache files.

### Task 1: Scaffold The Review Report And Lock The Source Set

**Files:**
- Create: `docs/superpowers/reports/2026-04-20-document-structure-review.md`

- [ ] **Step 1: Write the initial report scaffold**

```markdown
# agent-guard Documentation Structure Review

## Executive Summary

This review proposes a stable documentation structure for `agent-guard` after the execution-control narrative repositioning.

## Review Scope

This review covers tracked files under `docs/` plus tracked crate-level `README.md` files that act as developer-facing documentation.

## Target Structure Summary

This section defines the recommended long-term documentation layers.

## File Mapping Table

This section maps reviewed files to recommended structure layers and actions.

## Old Narrative Residue Table

This section identifies files that still use the old project narrative.

## Priority Action List

This section groups the recommended cleanup actions by priority.
```

- [ ] **Step 2: Verify the scaffold headings are present**

Run:

```bash
rg -n "^## (Executive Summary|Review Scope|Target Structure Summary|File Mapping Table|Old Narrative Residue Table|Priority Action List)$" docs/superpowers/reports/2026-04-20-document-structure-review.md
```

Expected: six matching heading lines in the report file.

- [ ] **Step 3: Record the tracked review source set in the report**

Append this block under `## Review Scope`:

```markdown
Tracked file discovery commands used for this review:

    git ls-files 'docs/**' 'crates/**/README.md' | sort

Review exclusions:

- untracked local process files
- generated cache files such as `crates/agent-guard-python/.pytest_cache/README.md`
- non-documentation scripts unless they are directly part of a tracked documentation surface
```

- [ ] **Step 4: Run the source-set command and spot-check the inputs**

Run:

```bash
git ls-files 'docs/**' 'crates/**/README.md' | sort
```

Expected:

- tracked `docs/` files appear
- `crates/agent-guard-node/README.md` appears
- `crates/agent-guard-python/README.md` appears
- `crates/agent-guard-python/.pytest_cache/README.md` does not appear

- [ ] **Step 5: Commit the scaffold**

```bash
git add docs/superpowers/reports/2026-04-20-document-structure-review.md
git commit -m "docs: scaffold documentation structure review report"
```

### Task 2: Write The Target Structure Summary

**Files:**
- Modify: `docs/superpowers/reports/2026-04-20-document-structure-review.md`
- Reference: `docs/superpowers/specs/2026-04-20-document-structure-and-cleanup-design.md`

- [ ] **Step 1: Replace the placeholder target-structure section with the six-layer model**

Write this section under `## Target Structure Summary`:

```markdown
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

- help a developer reach first understanding and first success quickly

Expected files:

- quick proof guides
- quickstarts
- first integration guides
- mode-selection guides

### 3. Integration / Reference

Role:

- help users choose an integration path and understand support boundaries

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

- retain historical and process context without presenting it as active product guidance

Expected files:

- archived phase documents
- superseded reports
- archived release support material
- superpowers process artifacts
```

- [ ] **Step 2: Add a short note on how to interpret actions**

Append this paragraph after the six layers:

```markdown
In the file mapping table below, `keep` means the file can remain in the active structure, `merge` means it overlaps with another file enough to justify later consolidation, `move down` means it should remain available but at lower prominence, `archive` means it should leave the active path while staying accessible, and `delete candidate` means its value appears weak enough that later removal should be considered.
```

- [ ] **Step 3: Verify the six layer headings exist**

Run:

```bash
rg -n "^### (1\\. Top-level entry points|2\\. Getting Started|3\\. Integration / Reference|4\\. Operations / Security|5\\. Adoption / Messaging|6\\. Archive / Internal Process)$" docs/superpowers/reports/2026-04-20-document-structure-review.md
```

Expected: six matching lines.

- [ ] **Step 4: Commit the structure summary**

```bash
git add docs/superpowers/reports/2026-04-20-document-structure-review.md
git commit -m "docs: define documentation structure review layers"
```

### Task 3: Populate The File Mapping Table For Entry, Getting Started, And Integration Docs

**Files:**
- Modify: `docs/superpowers/reports/2026-04-20-document-structure-review.md`

- [ ] **Step 1: Add the file-mapping table header**

Write this header under `## File Mapping Table`:

```markdown
| Path | Current role | Recommended layer | Action | Reason |
| :--- | :--- | :--- | :--- | :--- |
```

- [ ] **Step 2: Add rows for top-level entry and hub files**

Add rows covering these exact files:

- `README.md`
- `docs/README.md`
- `docs/architecture-and-vision.md`
- `docs/growth-and-adoption-plan.md`
- `docs/release-notes-v0.2.0.md`

Each row must assign one action from `keep`, `merge`, `move down`, `archive`, or `delete candidate`.

- [ ] **Step 3: Add rows for getting-started files**

Add rows covering these exact files:

- `docs/guides/getting-started/attack-demo-playbook.md`
- `docs/guides/getting-started/chatgpt-actions.md`
- `docs/guides/getting-started/check-vs-enforce.md`
- `docs/guides/getting-started/migration-guide.md`
- `docs/guides/getting-started/secure-shell-tools.md`
- `docs/guides/getting-started/three-minute-proof.md`
- `docs/guides/getting-started/trust-tooling.md`
- `docs/guides/getting-started/user-manual.md`

- [ ] **Step 4: Add rows for integration and reference files**

Add rows covering these exact files:

- `docs/adapter-contract.md`
- `docs/capability-parity.md`
- `docs/framework-support-matrix.md`
- `docs/m3.1-support-matrix.md`
- `docs/node-adapter-gap-report.md`
- `crates/agent-guard-node/README.md`
- `crates/agent-guard-python/README.md`

- [ ] **Step 5: Verify those rows exist**

Run:

```bash
rg -n "README.md|docs/README.md|architecture-and-vision|growth-and-adoption-plan|release-notes-v0.2.0|attack-demo-playbook|chatgpt-actions|check-vs-enforce|migration-guide|secure-shell-tools|three-minute-proof|trust-tooling|user-manual|adapter-contract|capability-parity|framework-support-matrix|m3.1-support-matrix|node-adapter-gap-report|crates/agent-guard-node/README.md|crates/agent-guard-python/README.md" docs/superpowers/reports/2026-04-20-document-structure-review.md
```

Expected: one matching row reference for each listed file.

- [ ] **Step 6: Commit the first mapping pass**

```bash
git add docs/superpowers/reports/2026-04-20-document-structure-review.md
git commit -m "docs: map entry and integration documents"
```

### Task 4: Populate The File Mapping Table For Operations, Adoption, And Historical Docs

**Files:**
- Modify: `docs/superpowers/reports/2026-04-20-document-structure-review.md`

- [ ] **Step 1: Add rows for operations and security files**

Add rows covering these exact files:

- `docs/guides/operations/deployment-guide.md`
- `docs/guides/operations/observability.md`
- `docs/research-appcontainer.md`
- `docs/sandbox-linux.md`
- `docs/sandbox-macos.md`
- `docs/sandbox-windows.md`
- `docs/security-audit.md`
- `docs/threat-model.md`

- [ ] **Step 2: Add rows for adoption and messaging files**

Add rows covering these exact files:

- `docs/guides/adoption/case-study-shell-agent.md`
- `docs/guides/adoption/demo-asset-workflow.md`
- `docs/guides/adoption/discussions-announcement.md`
- `docs/guides/adoption/external-channel-post-pack.md`
- `docs/guides/adoption/faq-for-new-users.md`
- `docs/guides/adoption/launch-kit.md`
- `docs/guides/adoption/release-announcement.md`
- `docs/guides/adoption/social-posts.md`

- [ ] **Step 3: Add rows for archive and internal-process files**

Add rows covering these exact files:

- `docs/archive/README.md`
- `docs/archive/phase2-design.md`
- `docs/archive/phase2-done.md`
- `docs/archive/phase3-design.md`
- `docs/archive/phase6-design.md`
- `docs/archive/phase8-design.md`
- `docs/archive/release-notes-v0.1.0.md`
- `docs/archive/sales-demo-script.md`
- `docs/superpowers/specs/2026-04-20-agent-runtime-control-diagnostic-design.md`
- `docs/superpowers/specs/2026-04-20-document-structure-and-cleanup-design.md`

- [ ] **Step 4: Verify the second-pass rows exist**

Run:

```bash
rg -n "deployment-guide|observability|research-appcontainer|sandbox-linux|sandbox-macos|sandbox-windows|security-audit|threat-model|case-study-shell-agent|demo-asset-workflow|discussions-announcement|external-channel-post-pack|faq-for-new-users|launch-kit|release-announcement|social-posts|docs/archive/README.md|phase2-design|phase2-done|phase3-design|phase6-design|phase8-design|release-notes-v0.1.0|sales-demo-script|agent-runtime-control-diagnostic-design|document-structure-and-cleanup-design" docs/superpowers/reports/2026-04-20-document-structure-review.md
```

Expected: one matching row reference for each listed file.

- [ ] **Step 5: Commit the second mapping pass**

```bash
git add docs/superpowers/reports/2026-04-20-document-structure-review.md
git commit -m "docs: map operations, adoption, and archive documents"
```

### Task 5: Build The Old Narrative Residue Table

**Files:**
- Modify: `docs/superpowers/reports/2026-04-20-document-structure-review.md`

- [ ] **Step 1: Add the old-narrative table header**

Write this header under `## Old Narrative Residue Table`:

```markdown
| Path | Old narrative type | Current layer or prominence | Severity | Reason |
| :--- | :--- | :--- | :--- | :--- |
```

- [ ] **Step 2: Run a keyword scan to collect candidate residue files**

Run:

```bash
rg -n "security runtime|security layer|AI Agents|control plane|Ecosystem|Trust|ecosystem integration|verifiable trust|high-performance security layer|AI security platform|pluggable, cross-framework|Agent Security Runtime" docs crates/*/README.md
```

Expected: matches in files such as `docs/README.md`, `docs/architecture-and-vision.md`, and any remaining package or support docs still using the older framing.

- [ ] **Step 3: Add explicit residue rows for high-severity entry-path files**

Review the scan output and add at least one row for every tracked high-severity file that still shapes first impressions. At minimum, evaluate and record rows for these files if they still match the old framing:

- `docs/README.md`
- `docs/architecture-and-vision.md`
- `docs/growth-and-adoption-plan.md`
- `docs/release-notes-v0.2.0.md`
- `crates/agent-guard-python/README.md`

- [ ] **Step 4: Add medium- and low-severity residue rows for supporting and historical files**

Review the remaining scan output and add rows for matching tracked files in:

- `docs/guides/adoption/`
- `docs/archive/`
- `docs/guides/getting-started/`
- `docs/guides/operations/`

Use only these severity labels:

- `high`
- `medium`
- `low`

- [ ] **Step 5: Verify the table contains severity labels and old-narrative categories**

Run:

```bash
rg -n "\| (high|medium|low) \||broad AI security platform framing|full control plane framing too early|ecosystem / trust presented as the main front-page hook|shell-first not framed as the current proof point" docs/superpowers/reports/2026-04-20-document-structure-review.md
```

Expected: matching lines from the old-narrative residue table.

- [ ] **Step 6: Commit the residue analysis**

```bash
git add docs/superpowers/reports/2026-04-20-document-structure-review.md
git commit -m "docs: identify old narrative residue in documentation"
```

### Task 6: Add The Priority Action List And Run The Final Consistency Pass

**Files:**
- Modify: `docs/superpowers/reports/2026-04-20-document-structure-review.md`

- [ ] **Step 1: Replace the placeholder priority section with three levels**

Write this section under `## Priority Action List`:

```markdown
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
```

- [ ] **Step 2: Add a short executive summary paragraph**

Replace the placeholder executive summary with a short paragraph that:

- states whether the main problem is structure, duplication, narrative residue, or a combination
- states whether the active path is currently too wide
- states whether the next cleanup should focus on P0 first

- [ ] **Step 3: Run the final structure checks**

Run:

```bash
rg -n "^## " docs/superpowers/reports/2026-04-20-document-structure-review.md
git diff --check -- docs/superpowers/reports/2026-04-20-document-structure-review.md
```

Expected:

- the report shows the six top-level sections from Task 1
- `git diff --check` prints nothing

- [ ] **Step 4: Run a quick completeness scan for the action vocabulary**

Run:

```bash
rg -n '`keep`|`merge`|`move down`|`archive`|`delete candidate`' docs/superpowers/reports/2026-04-20-document-structure-review.md
```

Expected: the report includes the action vocabulary definitions from the target-structure summary.

- [ ] **Step 5: Commit the completed review report**

```bash
git add docs/superpowers/reports/2026-04-20-document-structure-review.md
git commit -m "docs: complete documentation structure review"
```
