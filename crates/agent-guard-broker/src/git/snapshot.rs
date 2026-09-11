use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

use super::command::{failed, sanitized_git_command};
use super::validate::{
    read_single_push_url, reject_partial_clone, validate_push_target, validate_remote_url,
    validate_trusted_config_snapshot,
};
use super::{BrokerGitOptions, GitError};

pub(crate) struct GitSnapshot {
    _temp: TempDir,
    git_dir: PathBuf,
    trusted_config: PathBuf,
    hooks_dir: PathBuf,
    allow_local_file_remote: bool,
    pub(crate) remote_url: String,
}

impl GitSnapshot {
    pub(crate) fn capture(
        repo: &Path,
        remote: &str,
        branch: &str,
        options: &BrokerGitOptions,
    ) -> Result<Self, GitError> {
        validate_push_target(remote, branch)?;

        let repo = repo
            .canonicalize()
            .map_err(|error| GitError::UnsafeRepository {
                detail: format!(
                    "{} is not an accessible repository: {error}",
                    repo.display()
                ),
            })?;
        let source_git = repo.join(".git");
        require_plain_directory(&source_git, "the repository .git directory")?;

        let source_config = source_git.join("config");
        let source_config_bytes =
            read_plain_repository_file(&source_config, "the repository config")?;
        let temp = tempfile::tempdir()?;
        let source_config_snapshot = temp.path().join("source.gitconfig");
        fs::write(&source_config_snapshot, source_config_bytes)?;
        reject_partial_clone(&source_config_snapshot)?;
        let remote_url = read_single_push_url(&source_config_snapshot, remote)?;
        validate_remote_url(&remote_url, options.allow_local_file_remote)?;

        let trusted_bytes = read_trusted_config(options.trusted_config.as_deref(), &repo)?;
        let git_dir = temp.path().join("repo.git");
        let hooks_dir = temp.path().join("empty-hooks");
        fs::create_dir_all(git_dir.join("objects"))?;
        fs::create_dir_all(git_dir.join("refs/heads"))?;
        fs::create_dir_all(&hooks_dir)?;
        fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n")?;
        fs::write(
            git_dir.join("config"),
            b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
        )?;

        let trusted_config = temp.path().join("trusted.gitconfig");
        fs::write(&trusted_config, trusted_bytes)?;
        validate_trusted_config_snapshot(&trusted_config)?;

        copy_primary_objects(&source_git.join("objects"), &git_dir.join("objects"))?;
        copy_heads(&source_git.join("refs/heads"), &git_dir.join("refs/heads"))?;
        copy_packed_heads(
            &source_git.join("packed-refs"),
            &git_dir.join("packed-refs"),
        )?;
        copy_optional_plain_file(&source_git.join("shallow"), &git_dir.join("shallow"))?;

        let snapshot = Self {
            _temp: temp,
            git_dir,
            trusted_config,
            hooks_dir,
            allow_local_file_remote: options.allow_local_file_remote,
            remote_url,
        };

        let full_ref = format!("refs/heads/{branch}");
        snapshot.run(&["check-ref-format", &full_ref])?;
        let oid = snapshot.run(&["rev-parse", "--verify", &full_ref])?;
        snapshot.run(&["fsck", "--connectivity-only", &oid])?;
        Ok(snapshot)
    }

    pub(crate) fn run(&self, args: &[&str]) -> Result<String, GitError> {
        let output = self.output(args)?;
        if !output.status.success() {
            return Err(failed(args, output));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub(crate) fn status_is(
        &self,
        args: &[&str],
        expected_false_status: i32,
    ) -> Result<bool, GitError> {
        let output = self.output(args)?;
        if output.status.success() {
            return Ok(true);
        }
        if output.status.code() == Some(expected_false_status) {
            return Ok(false);
        }
        Err(failed(args, output))
    }

    pub(crate) fn run_optional(
        &self,
        args: &[&str],
        missing_status: i32,
    ) -> Result<Option<String>, GitError> {
        let output = self.output(args)?;
        if output.status.success() {
            return Ok(Some(
                String::from_utf8_lossy(&output.stdout).trim().to_string(),
            ));
        }
        if output.status.code() == Some(missing_status) {
            return Ok(None);
        }
        Err(failed(args, output))
    }

    pub(crate) fn push(&self, args: &[&str]) -> Result<String, GitError> {
        self.run(args)
    }

    /// Ask for one object's type without interpreting a generic fatal exit as
    /// the ordinary "object is absent" answer. Batch-check reports absence in
    /// its structured stdout and reserves a failed process for real Git
    /// errors.
    pub(crate) fn object_is_commit(&self, oid: &str) -> Result<bool, GitError> {
        let args = ["cat-file", "--batch-check=%(objectname) %(objecttype)"];
        let mut child = self
            .command(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| GitError::Unexpected {
                command: args.join(" "),
                detail: "git did not provide the requested stdin pipe".to_string(),
            })?
            .write_all(format!("{oid}\n").as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(failed(&args, output));
        }

        let answer = String::from_utf8_lossy(&output.stdout);
        let fields = answer.split_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            [reported_oid, "missing"] if *reported_oid == oid => Ok(false),
            [_reported_oid, "commit"] => Ok(true),
            _ => Err(GitError::Unexpected {
                command: args.join(" "),
                detail: answer.trim().to_string(),
            }),
        }
    }

    fn output(&self, args: &[&str]) -> Result<Output, GitError> {
        Ok(self.command(args).output()?)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = sanitized_git_command(&self.trusted_config);
        command
            .arg(format!("--git-dir={}", self.git_dir.display()))
            .args([
                "-c",
                &format!("core.hooksPath={}", self.hooks_dir.display()),
            ])
            .args(["-c", "protocol.allow=never"])
            .args(["-c", "protocol.https.allow=always"])
            .args(["-c", "protocol.ssh.allow=always"]);
        if self.allow_local_file_remote {
            command.args(["-c", "protocol.file.allow=always"]);
        }
        command.args(args).current_dir(self._temp.path());
        command
    }
}

fn read_trusted_config(path: Option<&Path>, repo: &Path) -> Result<Vec<u8>, GitError> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let before = fs::symlink_metadata(path)
        .map_err(|error| unsafe_config_file_error(path, "is not accessible", error))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(GitError::UnsafeConfig {
            detail: format!("{} is not a plain file", path.display()),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o022 != 0 {
            return Err(GitError::UnsafeConfig {
                detail: format!("{} is writable by group or others", path.display()),
            });
        }
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| GitError::UnsafeConfig {
            detail: format!("{} cannot be canonicalized: {error}", path.display()),
        })?;
    if canonical.starts_with(repo) {
        return Err(GitError::UnsafeConfig {
            detail: "the trusted config may not live inside the agent-writable repository"
                .to_string(),
        });
    }

    // Open the path that was checked, then bind every subsequent assertion to
    // that descriptor. Reading `canonical` with a second path lookup would
    // leave a rename/symlink window between the permission check and the bytes
    // that become the credential-bearing Git configuration.
    let mut file = File::open(path)
        .map_err(|error| unsafe_config_file_error(path, "could not be opened", error))?;
    let opened = file
        .metadata()
        .map_err(|error| unsafe_config_file_error(path, "could not be inspected", error))?;
    if !same_file_state(&before, &opened) {
        return Err(GitError::UnsafeConfig {
            detail: format!("{} changed while it was opened", path.display()),
        });
    }

    let mut body = Vec::new();
    file.read_to_end(&mut body)
        .map_err(|error| unsafe_config_file_error(path, "could not be read", error))?;
    let opened_after = file
        .metadata()
        .map_err(|error| unsafe_config_file_error(path, "could not be rechecked", error))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|error| unsafe_config_file_error(path, "could not be rechecked", error))?;
    let canonical_after = path
        .canonicalize()
        .map_err(|error| unsafe_config_file_error(path, "could not be recanonicalized", error))?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || canonical_after != canonical
        || !same_file_state(&before, &opened_after)
        || !same_file_state(&before, &path_after)
    {
        return Err(GitError::UnsafeConfig {
            detail: format!("{} changed while it was copied", path.display()),
        });
    }
    Ok(body)
}

fn unsafe_config_file_error(path: &Path, action: &str, error: std::io::Error) -> GitError {
    GitError::UnsafeConfig {
        detail: format!("{} {action}: {error}", path.display()),
    }
}

fn require_plain_directory(path: &Path, label: &str) -> Result<(), GitError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| GitError::UnsafeRepository {
        detail: format!("{label} {} is not accessible: {error}", path.display()),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GitError::UnsafeRepository {
            detail: format!("{label} must be a real directory; linked worktrees are unsupported"),
        });
    }
    Ok(())
}

fn read_plain_repository_file(path: &Path, label: &str) -> Result<Vec<u8>, GitError> {
    let (mut file, before) = open_plain_repository_file(path, label)?;
    let mut body = Vec::new();
    file.read_to_end(&mut body)
        .map_err(|error| unsafe_repository_file_error(path, label, error))?;
    verify_plain_repository_file(path, label, &file, &before)?;
    Ok(body)
}

fn copy_plain_repository_file(
    source: &Path,
    destination: &Path,
    label: &str,
) -> Result<(), GitError> {
    let (mut source_file, before) = open_plain_repository_file(source, label)?;
    let mut destination_file = File::create(destination)?;
    std::io::copy(&mut source_file, &mut destination_file)
        .map_err(|error| unsafe_repository_file_error(source, label, error))?;
    verify_plain_repository_file(source, label, &source_file, &before)
}

fn open_plain_repository_file(path: &Path, label: &str) -> Result<(File, Metadata), GitError> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| unsafe_repository_file_error(path, label, error))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(GitError::UnsafeRepository {
            detail: format!("{label} {} must be a regular file", path.display()),
        });
    }
    let file =
        File::open(path).map_err(|error| unsafe_repository_file_error(path, label, error))?;
    let opened = file
        .metadata()
        .map_err(|error| unsafe_repository_file_error(path, label, error))?;
    if !same_file_state(&before, &opened) {
        return Err(GitError::UnsafeRepository {
            detail: format!("{label} {} changed while it was opened", path.display()),
        });
    }
    Ok((file, before))
}

fn verify_plain_repository_file(
    path: &Path,
    label: &str,
    file: &File,
    before: &Metadata,
) -> Result<(), GitError> {
    let opened_after = file
        .metadata()
        .map_err(|error| unsafe_repository_file_error(path, label, error))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|error| unsafe_repository_file_error(path, label, error))?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || !same_file_state(before, &opened_after)
        || !same_file_state(before, &path_after)
    {
        return Err(GitError::UnsafeRepository {
            detail: format!("{label} {} changed while it was copied", path.display()),
        });
    }
    Ok(())
}

fn same_file_state(left: &Metadata, right: &Metadata) -> bool {
    if left.len() != right.len() || left.modified().ok() != right.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // ctime cannot be restored by an unprivileged writer after changing
        // bytes or metadata. Size + mtime alone can be forged back to their
        // earlier values and would not satisfy the snapshot's "changed while
        // copied" refusal guarantee.
        if left.dev() != right.dev()
            || left.ino() != right.ino()
            || left.ctime() != right.ctime()
            || left.ctime_nsec() != right.ctime_nsec()
        {
            return false;
        }
    }
    true
}

fn unsafe_repository_file_error(path: &Path, label: &str, error: std::io::Error) -> GitError {
    GitError::UnsafeRepository {
        detail: format!("{label} {} could not be copied: {error}", path.display()),
    }
}

fn copy_optional_plain_file(source: &Path, destination: &Path) -> Result<(), GitError> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(GitError::UnsafeRepository {
                detail: format!("{} must be a regular file", source.display()),
            })
        }
        Ok(_) => copy_plain_repository_file(source, destination, "repository data file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn copy_packed_heads(source: &Path, destination: &Path) -> Result<(), GitError> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(GitError::UnsafeRepository {
                detail: format!("{} must be a regular file", source.display()),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }

    let body =
        String::from_utf8(read_plain_repository_file(source, "packed refs")?).map_err(|error| {
            GitError::UnsafeRepository {
                detail: format!("{} is not valid packed-ref data: {error}", source.display()),
            }
        })?;
    let mut filtered = String::new();
    for line in body.lines() {
        let branch_ref = line.split_once(' ').is_some_and(|(_, name)| {
            name.starts_with("refs/heads/") && !name.chars().any(char::is_whitespace)
        });
        if line.starts_with('#') || branch_ref {
            filtered.push_str(line);
            filtered.push('\n');
        }
    }
    fs::write(destination, filtered)?;
    Ok(())
}

fn copy_heads(source: &Path, destination: &Path) -> Result<(), GitError> {
    if !source.exists() {
        return Ok(());
    }
    copy_regular_tree(source, destination, &|_| true)
}

fn copy_primary_objects(source: &Path, destination: &Path) -> Result<(), GitError> {
    require_plain_directory(source, "the primary object directory")?;
    let info = source.join("info");
    if info.exists() {
        require_plain_directory(&info, "the object info directory")?;
        for alternate in ["alternates", "http-alternates"] {
            if info.join(alternate).exists() {
                return Err(GitError::UnsafeRepository {
                    detail: "object alternates are not supported by the broker".to_string(),
                });
            }
        }
    }

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(GitError::UnsafeRepository {
                detail: format!(
                    "object-store symlink {} is not allowed",
                    entry.path().display()
                ),
            });
        }
        if name == "pack" && file_type.is_dir() {
            if entry.path().read_dir()?.any(|item| {
                item.ok().is_some_and(|item| {
                    item.path().extension().is_some_and(|ext| ext == "promisor")
                })
            }) {
                return Err(GitError::UnsafeRepository {
                    detail: "partial-clone promisor packs are not supported".to_string(),
                });
            }
            copy_regular_tree(&entry.path(), &destination.join("pack"), &|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack" || extension == "idx")
            })?;
        } else if file_type.is_dir()
            && name.len() == 2
            && name.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            copy_regular_tree(&entry.path(), &destination.join(name.as_ref()), &|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.len() == 38 && name.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
            })?;
        }
    }
    Ok(())
}

fn copy_regular_tree(
    source: &Path,
    destination: &Path,
    include: &dyn Fn(&Path) -> bool,
) -> Result<(), GitError> {
    require_plain_directory(source, "repository data directory")?;
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(GitError::UnsafeRepository {
                detail: format!(
                    "repository-data symlink {} is not allowed",
                    entry.path().display()
                ),
            });
        }
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_regular_tree(&entry.path(), &target, include)?;
        } else if file_type.is_file() && include(&entry.path()) {
            copy_plain_repository_file(&entry.path(), &target, "repository data file")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_refs_copy_only_local_branch_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        let oid = "1111111111111111111111111111111111111111";
        fs::write(
            &source,
            format!(
                "# pack-refs with: peeled fully-peeled sorted\n\
                 {oid} refs/heads/main\n\
                 {oid} refs/tags/release\n\
                 ^{oid}\n\
                 {oid} refs/replace/{oid}\n"
            ),
        )
        .expect("source");

        copy_packed_heads(&source, &destination).expect("copy");
        let copied = fs::read_to_string(destination).expect("destination");

        assert!(copied.contains("refs/heads/main"));
        assert!(!copied.contains("refs/tags"));
        assert!(!copied.contains("refs/replace"));
        assert!(!copied.lines().any(|line| line.starts_with('^')));
    }
}
