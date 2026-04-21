# File Path Validator Parity Design

## Summary

This design narrows issue `#3` to the highest-risk gap first: `read_file` and `write_file` should no longer rely only on string-level payload extraction and policy glob matching. They should get a shared path validation layer that normalizes paths, resolves trusted roots relative to the request context, and fails closed on symlink escape attempts.

## Goal

Bring `read_file` and `write_file` closer to the depth of the existing Bash validator without widening runtime scope, changing the public API, or redesigning HTTP policy semantics in the same change.

## In Scope

- shared path normalization for `read_file` and `write_file`
- relative path resolution against `Context.working_directory`
- existing-path canonicalization before allow/deny decisions
- parent-directory canonicalization for write targets that do not yet exist
- symlink escape detection for allowlisted writes and denied reads
- targeted tests for traversal, relative-path escape, and symlink escape

## Out of Scope

- HTTP method-aware policy redesign
- new binding APIs
- changing the existing YAML policy schema
- broad validator parity across every tool in one pass

## Current Problem

Today:

- payload extraction returns the raw `path` string from JSON
- policy matching evaluates that string against `allow_paths` and `deny_paths`
- `execute_write_file()` opens the path directly from the payload

That leaves asymmetric depth compared with Bash:

- `../` traversal can be represented several ways before normalization
- relative paths depend on caller context but are not normalized consistently
- symlinked paths can appear to match an allowlist lexically while resolving outside it

## Proposed Approach

Add a shared file-path guard layer in `agent-guard-core` and use it from the policy engine before path-based matching.

The layer should:

1. parse the payload path as today
2. resolve relative paths against `Context.working_directory` when present
3. lexically normalize the path
4. canonicalize the path when it exists
5. for a non-existent write target, canonicalize the nearest existing parent and reattach the remaining suffix
6. detect symlink escapes by comparing the resolved path against configured allow/deny roots
7. return a normalized path string for downstream policy matching

This keeps policy YAML unchanged while making the existing checks act on a safer representation.

## Decision Rules

For `read_file`:

- match `deny_paths` and `allow_paths` against the normalized/resolved path, not the raw payload string
- if resolution shows the target escapes the intended root through symlinks or traversal, deny before rule evaluation completes

For `write_file`:

- normalize the target path before allowlist evaluation
- if the destination does not exist, resolve the nearest existing parent directory first
- if the resolved target escapes the allowlisted tree through a symlinked parent, deny

## Error Handling

The new path layer should fail closed and map to existing decision semantics:

- malformed or empty paths continue to deny as invalid payload
- missing working directory for relative-path cases should not panic; use current behavior and deny only when normalization or policy checks cannot safely proceed
- filesystem resolution errors should preserve a clear deny reason instead of falling through to raw-string matching

## Testing Strategy

Add focused tests for:

- `read_file` with `../` traversal outside the trusted workspace
- `write_file` with a relative path that resolves outside the allowlisted root
- `write_file` through a symlink inside the workspace pointing outside the allowlisted root
- `read_file` through a symlink that resolves into a denied path
- a normal allowlisted nested path still succeeds

## Expected Outcome

After this change, `read_file` and `write_file` still use the existing policy schema and runtime APIs, but the boundary becomes meaningfully harder to bypass with path-shape tricks. This closes the highest-risk inconsistency called out in the review without turning the change into a full validator framework rewrite.
