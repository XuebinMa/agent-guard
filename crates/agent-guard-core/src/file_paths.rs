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

    resolve_with_existing_ancestor(&normalized)
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

fn resolve_with_existing_ancestor(path: &Path) -> Result<PathBuf, GuardDecision> {
    let mut current = path;
    let mut suffix: Vec<OsString> = Vec::new();

    loop {
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
                return Ok(resolved);
            }
            Err(_) => {
                let Some(parent) = current.parent() else {
                    return Ok(path.to_path_buf());
                };

                let Some(file_name) = current.file_name() else {
                    return Ok(path.to_path_buf());
                };

                suffix.push(file_name.to_os_string());
                current = parent;
            }
        }
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
    fn resolves_symlinked_existing_paths_to_canonical_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("workspace");
        std::fs::create_dir_all(&outside).expect("outside");

        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "shh").expect("seed");
        let link = workspace.join("linked.txt");
        symlink_path(&outside_file, &link);

        let resolved =
            resolve_tool_path(link.to_str().expect("path str"), Some(&workspace)).expect("resolve");

        assert_eq!(resolved, outside_file.canonicalize().expect("canonical"));
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
