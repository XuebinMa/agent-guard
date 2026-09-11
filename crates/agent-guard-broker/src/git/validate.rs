use std::path::Path;

use super::command::{config_names, config_values};
use super::GitError;

/// Reject values that are safe as argv but unsafe to restate as an advisory
/// shell command or policy subject.
pub fn validate_push_target(remote: &str, branch: &str) -> Result<(), GitError> {
    if !safe_cli_atom(remote) {
        return Err(GitError::InvalidTarget {
            detail: format!(
                "remote name {remote:?} is outside the broker's safe ASCII grammar; create or use \
                 an alias that begins with a letter or digit and contains only letters, digits, \
                 '.', '_', '/', or '-'"
            ),
        });
    }
    if !safe_cli_atom(branch) || !valid_branch_shape(branch) {
        return Err(GitError::InvalidTarget {
            detail: format!(
                "branch name {branch:?} is outside the broker's supported safe grammar; rename or \
                 create a branch that begins with a letter or digit and contains only letters, \
                 digits, '.', '_', '/', or '-'"
            ),
        });
    }
    Ok(())
}

fn safe_cli_atom(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/' | '-'))
}

fn valid_branch_shape(branch: &str) -> bool {
    branch != "@"
        && !branch.contains("..")
        && !branch.contains("//")
        && !branch.contains("@{")
        && !branch.ends_with('.')
        && branch
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

pub(super) fn read_single_push_url(config: &Path, remote: &str) -> Result<String, GitError> {
    let push_urls = config_values(config, &format!("remote.{remote}.pushurl"))?;
    let urls = if push_urls.is_empty() {
        config_values(config, &format!("remote.{remote}.url"))?
    } else {
        push_urls
    };
    match urls.as_slice() {
        [url] if !url.is_empty() => Ok(url.clone()),
        [url] if url.is_empty() => Err(GitError::UnsafeRemote {
            detail: format!("remote {remote:?} has an empty push destination"),
        }),
        [] => Err(GitError::UnsafeRemote {
            detail: format!("remote {remote:?} has no repository-local URL"),
        }),
        _ => Err(GitError::UnsafeRemote {
            detail: format!("remote {remote:?} has several push destinations"),
        }),
    }
}

pub(super) fn validate_remote_url(url: &str, allow_local: bool) -> Result<(), GitError> {
    if url.chars().any(char::is_control) || url.chars().any(char::is_whitespace) {
        return Err(GitError::UnsafeRemote {
            detail: "the remote URL contains whitespace or control characters".to_string(),
        });
    }
    let secure_network =
        url.starts_with("https://") || url.starts_with("ssh://") || is_scp_style_ssh(url);
    let local = url.starts_with("file://") || Path::new(url).is_absolute();
    if secure_network || (allow_local && local) {
        return Ok(());
    }
    Err(GitError::UnsafeRemote {
        detail: format!("protocol for {url:?} is not allowed"),
    })
}

fn is_scp_style_ssh(url: &str) -> bool {
    let Some((authority, path)) = url.split_once(':') else {
        return false;
    };
    if authority.is_empty()
        || authority.contains('/')
        || path.is_empty()
        || path.starts_with(':')
        || (authority.len() == 1
            && authority.as_bytes()[0].is_ascii_alphabetic()
            && (path.starts_with('/') || path.starts_with('\\')))
        || url.contains("://")
    {
        return false;
    }
    let (user, host) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(user, host)| (Some(user), host));
    let safe_component = |value: &str| {
        !value.is_empty()
            && value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    };
    safe_component(host)
        && host
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && match user {
            Some(user) => safe_component(user),
            None => true,
        }
        && !path.is_empty()
}

pub(super) fn reject_partial_clone(config: &Path) -> Result<(), GitError> {
    for name in config_names(config)? {
        let lower = name.to_ascii_lowercase();
        if lower == "extensions.partialclone" || lower.ends_with(".promisor") {
            return Err(GitError::UnsafeRepository {
                detail: "partial-clone repositories are not supported by the broker".to_string(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_trusted_config_snapshot(config: &Path) -> Result<(), GitError> {
    for name in config_names(config)? {
        let lower = name.to_ascii_lowercase();
        let allowed = lower.starts_with("credential.")
            || lower.starts_with("http.")
            || lower == "ssh.variant";
        if !allowed {
            return Err(GitError::UnsafeConfig {
                detail: format!("key {name:?} is not allowed"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_values_are_restricted_to_unquoted_cli_atoms() {
        assert!(validate_push_target("origin", "feature/safe-name_1").is_ok());
        for bad in [
            "-origin",
            "_origin",
            "bad remote",
            "origin;touch",
            "origin$(id)",
        ] {
            let error = validate_push_target(bad, "main").expect_err(bad);
            assert!(error.to_string().contains("create or use an alias"));
        }
        for bad in [
            "-main",
            "_wip",
            "含非ASCII",
            "feature+a",
            "bad branch",
            "main;touch",
            "a..b",
            ".hidden",
        ] {
            let error = validate_push_target("origin", bad).expect_err(bad);
            assert!(error.to_string().contains("rename or create a branch"));
        }
    }

    #[test]
    fn transport_policy_is_closed_by_default() {
        for allowed in [
            "https://example.invalid/repo.git",
            "ssh://git@example.invalid/repo.git",
            "git@example.invalid:repo.git",
            "hostalias:repo.git",
        ] {
            assert!(validate_remote_url(allowed, false).is_ok(), "{allowed}");
        }
        for refused in [
            "http://example.invalid/repo.git",
            "git://example.invalid/repo.git",
            "ext::sh -c whoami",
            "custom::address",
            "-oProxyCommand=evil:repo.git",
            "C:\\repo.git",
            "/tmp/repo.git",
            "file:///tmp/repo.git",
            "custom://example.invalid/repo.git",
        ] {
            assert!(validate_remote_url(refused, false).is_err(), "{refused}");
        }
        assert!(validate_remote_url("/tmp/repo.git", true).is_ok());
    }
}
