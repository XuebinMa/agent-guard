use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::{DecisionCode, GuardDecision};

pub fn resolve_tool_path(
    raw_path: &str,
    working_directory: Option<&Path>,
) -> Result<PathBuf, GuardDecision> {
    if raw_path.trim().is_empty() {
        return Err(GuardDecision::deny(
            DecisionCode::InvalidPayload,
            "path must not be empty",
        ));
    }

    let path = Path::new(raw_path);
    let anchored = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(working_directory) = working_directory {
        working_directory.join(path)
    } else {
        path.to_path_buf()
    };
    let normalized = normalize_path(&anchored);

    resolve_with_existing_ancestor(&normalized, working_directory)
}

pub fn resolve_path_glob_pattern(pattern: &str, working_directory: Option<&Path>) -> String {
    let Some(split_index) = pattern.find(['*', '?', '[']) else {
        return resolve_tool_path(pattern, working_directory)
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|_| pattern.to_string());
    };

    let (prefix, suffix) = pattern.split_at(split_index);
    if prefix.is_empty() {
        return pattern.to_string();
    }

    let resolved_prefix = resolve_tool_path(prefix, working_directory)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| prefix.to_string());

    if suffix.is_empty() {
        return resolved_prefix;
    }

    if resolved_prefix.ends_with(std::path::MAIN_SEPARATOR) {
        format!("{resolved_prefix}{suffix}")
    } else {
        format!("{resolved_prefix}{}{suffix}", std::path::MAIN_SEPARATOR)
    }
}

fn resolve_with_existing_ancestor(
    path: &Path,
    workspace_bound: Option<&Path>,
) -> Result<PathBuf, GuardDecision> {
    let mut current = path;
    let mut suffix: Vec<OsString> = Vec::new();

    let resolved = loop {
        match std::fs::symlink_metadata(current) {
            Ok(_) => {
                let mut resolved = std::fs::canonicalize(current).map_err(|error| {
                    GuardDecision::deny(
                        DecisionCode::UntrustedPath,
                        format!("failed to resolve path '{}': {error}", current.display()),
                    )
                })?;
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                break resolved;
            }
            Err(_) => {
                let Some(parent) = current.parent() else {
                    return enforce_workspace_bound(path.to_path_buf(), workspace_bound);
                };

                let Some(file_name) = current.file_name() else {
                    return enforce_workspace_bound(path.to_path_buf(), workspace_bound);
                };

                suffix.push(file_name.to_os_string());
                current = parent;
            }
        }
    };

    enforce_workspace_bound(resolved, workspace_bound)
}

/// Reject any resolved path that escapes the workspace bound (when one
/// was provided). Closes the 2026-05-15 HIGH path-traversal: ancestor
/// canonicalization can resolve through a symlink and silently land
/// outside the workspace; the suffix re-append then propagates the
/// escape. Callers that pass `working_directory = None` opt out of this
/// confinement and are presumed to enforce policy elsewhere.
fn enforce_workspace_bound(
    resolved: PathBuf,
    workspace_bound: Option<&Path>,
) -> Result<PathBuf, GuardDecision> {
    let Some(bound) = workspace_bound else {
        return Ok(resolved);
    };

    // Canonicalize the bound itself so platform-specific aliases (e.g.
    // `/tmp` → `/private/tmp` on macOS) do not cause a spurious mismatch.
    // Fall back to the lexical form if canonicalization fails (e.g. the
    // bound directory was not yet created); in that case the prefix check
    // is best-effort but still fails closed if the resolved path is clearly
    // unrelated.
    let canonical_bound = std::fs::canonicalize(bound).unwrap_or_else(|_| bound.to_path_buf());

    if resolved.starts_with(&canonical_bound) {
        Ok(resolved)
    } else {
        Err(GuardDecision::deny(
            DecisionCode::PathTraversal,
            format!(
                "path '{}' resolves outside the workspace ('{}')",
                resolved.display(),
                canonical_bound.display()
            ),
        ))
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !path.is_absolute() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::{resolve_path_glob_pattern, resolve_tool_path};

    #[test]
    fn resolves_relative_paths_against_working_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(workspace.join("src")).expect("workspace");

        let resolved =
            resolve_tool_path("./src/../src/file.txt", Some(&workspace)).expect("resolve");

        assert_eq!(
            resolved,
            workspace
                .join("src")
                .canonicalize()
                .expect("canonical workspace src")
                .join("file.txt")
        );
    }

    #[test]
    fn rejects_symlink_target_outside_workspace() {
        // Closes 2026-05-15 HIGH path-traversal: a workspace-internal
        // symlink whose target lies outside the workspace must not yield
        // an out-of-workspace canonical path. Replaces the prior test
        // that documented the bug as an accepted behaviour.
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("workspace");
        std::fs::create_dir_all(&outside).expect("outside");

        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "shh").expect("seed");
        let link = workspace.join("linked.txt");
        symlink_path(&outside_file, &link);

        let err = resolve_tool_path(link.to_str().expect("path str"), Some(&workspace))
            .expect_err("symlink target outside workspace must error");
        assert_path_traversal(&err);
    }

    #[test]
    fn rejects_ancestor_symlink_outside_workspace_for_nonexistent_leaf() {
        // The exact attack from the audit: `/workspace/link/cron.d/backdoor`
        // where `/workspace/link → /outside`. `resolve_with_existing_ancestor`
        // walked up to `/workspace/link`, canonicalized it to `/outside`,
        // and re-appended `cron.d/backdoor` — silently returning a host path.
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("workspace");
        std::fs::create_dir_all(&outside).expect("outside");

        let link = workspace.join("link");
        symlink_path(&outside, &link);

        let target = link.join("cron.d").join("backdoor");

        let err = resolve_tool_path(target.to_str().expect("path str"), Some(&workspace))
            .expect_err("ancestor symlink to outside must error");
        assert_path_traversal(&err);
    }

    #[test]
    fn allows_in_workspace_symlink_to_in_workspace_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("workspace");

        let target_file = workspace.join("real.txt");
        std::fs::write(&target_file, "real").expect("seed");
        let link = workspace.join("alias.txt");
        symlink_path(&target_file, &link);

        let resolved = resolve_tool_path(link.to_str().expect("path"), Some(&workspace))
            .expect("in-workspace symlink should resolve");
        assert_eq!(resolved, target_file.canonicalize().expect("canonical"));
    }

    #[test]
    fn rejects_absolute_path_outside_workspace_when_bound_provided() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("workspace");
        std::fs::create_dir_all(&outside).expect("outside");

        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "shh").expect("seed");

        let err = resolve_tool_path(outside_file.to_str().expect("path str"), Some(&workspace))
            .expect_err("absolute path outside workspace must error");
        assert_path_traversal(&err);
    }

    #[test]
    fn allows_absolute_path_when_no_workspace_bound() {
        // When `working_directory` is None the resolver makes no bound
        // assertion — preserves the contract for callers that enforce
        // policy elsewhere (e.g. raw tooling that resolves a path for
        // diagnostic display).
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("anywhere.txt");
        std::fs::write(&file, "x").expect("seed");

        let resolved = resolve_tool_path(file.to_str().expect("path"), None).expect("resolve");
        assert_eq!(resolved, file.canonicalize().expect("canonical"));
    }

    fn assert_path_traversal(err: &crate::GuardDecision) {
        match err {
            crate::GuardDecision::Deny { reason } => {
                assert_eq!(
                    reason.code,
                    crate::DecisionCode::PathTraversal,
                    "expected PathTraversal, got {:?}: {}",
                    reason.code,
                    reason.message
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn resolves_glob_patterns_through_existing_prefixes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("workspace");

        let resolved = resolve_path_glob_pattern(
            &format!("{}/**", workspace.display()),
            Some(workspace.as_path()),
        );

        assert!(resolved.ends_with(&format!("{}**", std::path::MAIN_SEPARATOR)));
        assert!(resolved.starts_with(
            workspace
                .canonicalize()
                .expect("canonical workspace")
                .to_string_lossy()
                .as_ref()
        ));
    }

    #[cfg(unix)]
    fn symlink_path(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).expect("create symlink");
    }

    #[cfg(windows)]
    fn symlink_path(target: &std::path::Path, link: &std::path::Path) {
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link).expect("create dir symlink");
        } else {
            std::os::windows::fs::symlink_file(target, link).expect("create file symlink");
        }
    }
}
