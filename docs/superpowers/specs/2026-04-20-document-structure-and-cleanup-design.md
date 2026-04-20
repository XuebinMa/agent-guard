# agent-guard Documentation Structure And Cleanup Design

## Metadata

- Date: 2026-04-20
- Author: Codex
- Status: Approved in conversation, written for review
- Primary audience: Maintainers and documentation owners
- Primary target user: Repository maintainers deciding how to reorganize docs
- Work type: Documentation information architecture review

## Goal

Produce a repository-level documentation inventory and structure proposal for `agent-guard` that answers four questions:

1. What stable document structure should the project use after the narrative repositioning?
2. Which existing files belong in that structure as-is?
3. Which files should be merged, moved down, archived, or considered for removal?
4. Which files still speak in the old narrative and therefore need follow-up rewriting later?

This work is not a content rewrite pass. It is a structure-first diagnostic and cleanup design for the current documentation set.

## Scope

### In scope

- The full `docs/` tree
- Root documentation entry points that shape doc discovery
- Crate-level `README.md` files that act as developer-facing entry docs
- The relationship between top-level docs, support docs, archive docs, and internal process artifacts
- Identification of files that still use the old narrative

### Out of scope

- Rewriting document content in this phase
- Editing or deleting files in this phase
- Reviewing every script, config, or code comment outside the documentation surface
- Auditing code correctness or implementation quality
- Building a final migration plan for every file

## Analysis Frame

The documentation review should use three lenses:

1. Structure clarity
   - Can a new developer understand where to start and where deeper material lives?
2. Role clarity
   - Does each document have a distinct purpose, or is it duplicating another file?
3. Narrative alignment
   - Does the document still present `agent-guard` through the old broad platform story, or through the new execution-control story?

## Current Repository Reality

The repository has already repositioned its top-level narrative around:

- `execution control layer for agent side effects`
- AI application and agent developers as the first target user
- shell-first enforcement as the current proof point
- policy workflow and control-plane ambitions as later-stage expansion, not the first hook

But the documentation tree still mixes several kinds of material at once:

- top-level onboarding and product entry points
- integration and support references
- operations and security reviews
- DevRel and adoption assets
- historical milestone and phase material
- superpowers process artifacts and planning material

That mixture makes the docs harder to navigate and makes old narrative residue harder to spot.

## Proposed Target Documentation Structure

The inventory should evaluate the repository against six stable layers:

### 1. Top-level entry points

Purpose:

- define what the project is
- send new users to the right next step
- establish the current narrative clearly

Expected files:

- `README.md`
- `docs/README.md`

### 2. Getting Started

Purpose:

- help a developer understand value and reach first success in minutes

Expected files:

- quick proofs
- quickstarts
- first integration guides
- mode-selection guidance

### 3. Integration / Reference

Purpose:

- help users choose and understand integration paths
- document adapters, capability boundaries, support levels, and package entry points

Expected files:

- support matrices
- adapter contracts
- capability references
- crate READMEs that function as integration docs

### 4. Operations / Security

Purpose:

- support operators, security reviewers, and maintainers working on real deployment boundaries

Expected files:

- threat model
- deployment guide
- observability
- security audit
- platform sandbox documents

### 5. Adoption / Messaging

Purpose:

- hold reusable public-facing explanation and launch assets without crowding the product entry path

Expected files:

- launch kit
- release announcement drafts
- case studies
- FAQ
- social and external channel packs

### 6. Archive / Internal Process

Purpose:

- keep historical context and process records available without presenting them as active product docs

Expected files:

- phase documents
- archived release artifacts
- superseded reports
- superpowers plans and process files

## Deliverables

The review should produce three explicit outputs.

### Deliverable 1: Target structure summary

This section explains:

- the six structure layers
- the responsibility of each layer
- which document types belong in each layer
- which document types should not remain on the main developer path

### Deliverable 2: File mapping table

Every reviewed file should be mapped with:

- path
- current role
- recommended structure layer
- recommended action
- short reason

The action vocabulary should be:

- `keep`
- `merge`
- `move down`
- `archive`
- `delete candidate`

These actions mean:

- `keep`: the file has a clear role and can stay in the active structure
- `merge`: the file overlaps heavily with another file and should likely be consolidated later
- `move down`: the file is useful but should not sit on the primary path or current level of prominence
- `archive`: the file is historical, transitional, or process-oriented and should be kept out of the active doc path
- `delete candidate`: the file appears redundant or low-value enough that later removal should be considered

### Deliverable 3: Old narrative residue table

This table should cover:

- the full `docs/` tree
- crate-level `README.md` files

Each entry should include:

- path
- old narrative type
- current layer or prominence
- severity
- short reason

The old narrative categories should include:

- broad AI security platform framing
- full control plane framing too early
- ecosystem / trust presented as the main front-page hook
- shell-first not framed as the current proof point
- other wording that pulls the project away from the execution-control positioning

Severity should be:

- `high`: likely to distort first impressions or key developer understanding
- `medium`: misaligned supporting material that does not define the first-contact story
- `low`: historical or secondary material with limited discovery impact

## Review Style

The review should be balanced rather than conservative or aggressive.

That means:

- obvious duplication should be called out
- movement into lower-prominence layers should be suggested when useful
- archival should be recommended for process and transition material
- deletion should be suggested cautiously and only when value looks weak

The goal is to reduce confusion without over-pruning legitimate supporting material.

## Decisions Made During Brainstorming

- The review should cover the full `docs/` information architecture, not just the onboarding path
- The preferred output is a target structure with file mappings, not only a cleanup checklist
- The review style should be balanced
- Files that still use the old narrative must be called out in a dedicated table
- The old-narrative table should cover the entire `docs/` tree plus crate READMEs
- This phase should not yet rewrite documents or perform cleanup edits

## Success Criteria

This design should be considered successful if the resulting review makes the following decisions easy:

1. Which docs form the active developer-facing path after the repositioning?
2. Which docs are supporting but too prominent today?
3. Which docs are mainly historical or process artifacts?
4. Which docs still pull the project back toward the old narrative?

If the review cannot answer those four questions cleanly, the structure design is still too vague.
