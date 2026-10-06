use std::path::Path;

use url::Url;

use super::command::config_values;
use super::GitError;

#[derive(Debug)]
pub(super) struct AuthenticationPolicy {
    scopes: Vec<Url>,
}

impl AuthenticationPolicy {
    pub(super) fn from_config(config: &Path, names: &[String]) -> Result<Self, GitError> {
        let mut scopes = Vec::new();
        for name in names {
            let lower = name.to_ascii_lowercase();
            if lower.starts_with("credential.") && lower.ends_with(".usehttppath") {
                for value in config_values(config, name)? {
                    if !matches!(
                        value.to_ascii_lowercase().as_str(),
                        "true" | "yes" | "on" | "1"
                    ) {
                        return Err(unsafe_config(format!(
                            "key {name:?} must be true: credential helpers must receive the repository path"
                        )));
                    }
                }
            }
            let (section, leaf) = if lower.starts_with("credential.") && lower.ends_with(".helper")
            {
                ("credential", "helper")
            } else if lower.starts_with("http.") && lower.ends_with(".extraheader") {
                ("http", "extraheader")
            } else {
                continue;
            };
            // Inspect every value, not just the last or most-specific one:
            // Git chains all matching helpers and an empty value resets them.
            if config_values(config, name)?.iter().all(String::is_empty) {
                continue;
            }
            let scope_start = section.len() + 1;
            let scope_end = name.len() - leaf.len() - 1;
            if scope_end <= scope_start {
                return Err(unsafe_config(format!(
                    "key {name:?} applies to every host; scope it to one destination, e.g. \
                     [{section} \"https://host/\"] {leaf} = …"
                )));
            }
            // Section/key names are case-insensitive, URL paths are not.
            scopes.push(canonical_auth_url(&name[scope_start..scope_end])?);
        }
        Ok(Self { scopes })
    }

    pub(super) fn authorize_destination(&self, remote_url: &str) -> Result<(), GitError> {
        // HTTPS settings do not authenticate SSH/SCP or explicit local test
        // transports; those retain their separate protocol/host trust boundary.
        if self.scopes.is_empty() || !remote_url.starts_with("https://") {
            return Ok(());
        }
        let destination = canonical_auth_url(remote_url)?;
        if self
            .scopes
            .iter()
            .any(|scope| scope_matches(scope, &destination))
        {
            return Ok(());
        }
        Err(unsafe_config(
            "the push URL is outside every trusted authentication scope; configure an explicit \
             HTTPS helper/header scope for the intended destination before previewing it"
                .to_string(),
        ))
    }
}

fn canonical_auth_url(raw: &str) -> Result<Url, GitError> {
    let parsed = Url::parse(raw).map_err(|_| unsafe_scope(raw))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !raw.chars().all(|ch| ch.is_ascii_graphic())
        || raw.contains(['%', '\\', '*', '?'])
        || parsed.as_str() != raw
    {
        return Err(unsafe_scope(raw));
    }
    Ok(parsed)
}

fn scope_matches(scope: &Url, destination: &Url) -> bool {
    // Git treats one trailing scope slash as implicit at a path boundary.
    let scope_path = scope.path().strip_suffix('/').unwrap_or(scope.path());
    scope.scheme() == destination.scheme()
        && scope.host_str() == destination.host_str()
        && scope.port_or_known_default() == destination.port_or_known_default()
        && (scope_path == destination.path()
            || destination
                .path()
                .strip_prefix(scope_path)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

fn unsafe_scope(raw: &str) -> GitError {
    unsafe_config(format!(
        "authentication URL {raw:?} must be a canonical HTTPS URL with an exact host and optional \
         repository path; no userinfo, wildcard, escapes, query, fragment, or normalization aliases"
    ))
}

fn unsafe_config(detail: String) -> GitError {
    GitError::UnsafeConfig { detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_scope_matches_authority_and_path_components() {
        let scope = canonical_auth_url("https://approved.invalid:8443/Team/repo.git").unwrap();
        for target in [
            "https://approved.invalid:8443/Team/repo.git",
            "https://approved.invalid:8443/Team/repo.git/child",
        ] {
            assert!(scope_matches(&scope, &canonical_auth_url(target).unwrap()));
        }
        for target in [
            "https://other.invalid:8443/Team/repo.git",
            "https://approved.invalid/Team/repo.git",
            "https://approved.invalid:8443/Team/repo.git-sibling",
            "https://approved.invalid:8443/team/repo.git",
        ] {
            assert!(
                !scope_matches(&scope, &canonical_auth_url(target).unwrap()),
                "{target}"
            );
        }
        let root = canonical_auth_url("https://approved.invalid/").unwrap();
        assert!(scope_matches(
            &root,
            &canonical_auth_url("https://approved.invalid/any.git").unwrap()
        ));
        let trailing = canonical_auth_url("https://approved.invalid:8443/Team/repo.git/").unwrap();
        assert!(scope_matches(&trailing, &scope));
        let doubled = canonical_auth_url("https://approved.invalid:8443/Team/repo.git//").unwrap();
        assert!(
            !scope_matches(&doubled, &scope),
            "do not erase repeated slashes"
        );
    }

    #[test]
    fn https_helpers_do_not_change_other_transport_authority() {
        let policy = AuthenticationPolicy {
            scopes: vec![canonical_auth_url("https://approved.invalid/").unwrap()],
        };
        for other in [
            "ssh://git@ssh-host.invalid/repo.git",
            "git@ssh-host.invalid:repo.git",
            "/local/test.git",
        ] {
            assert!(policy.authorize_destination(other).is_ok());
        }
    }
}
