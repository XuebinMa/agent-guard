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

## Old Narrative Residue Table

This section identifies files that still use the old project narrative.

## Priority Action List

This section groups the recommended cleanup actions by priority.
