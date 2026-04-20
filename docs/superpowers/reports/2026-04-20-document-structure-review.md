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

This section defines the recommended long-term documentation layers.

## File Mapping Table

This section maps reviewed files to recommended structure layers and actions.

## Old Narrative Residue Table

This section identifies files that still use the old project narrative.

## Priority Action List

This section groups the recommended cleanup actions by priority.
