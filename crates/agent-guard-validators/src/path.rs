use std::path::{Path, PathBuf};

// Ported from trust_resolver.rs — minimal changes to use/import paths only.

const TRUST_PROMPT_CUES: &[&str] = &[
    "do you trust the files in this folder",
    "trust the files in this folder",
    "trust this folder",
    "allow and continue",
    "yes, proceed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicy {
    AutoTrust,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEvent {
    TrustRequired { cwd: String },
    TrustResolved { cwd: String, policy: TrustPolicy },
    TrustDenied { cwd: String, reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct TrustConfig {
    allowlisted: Vec<PathBuf>,
    denied: Vec<PathBuf>,
}

impl TrustConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_allowlisted(mut self, path: impl Into<PathBuf>) -> Self {
        self.allowlisted.push(path.into());
        self
    }

    #[must_use]
    pub fn with_denied(mut self, path: impl Into<PathBuf>) -> Self {
        self.denied.push(path.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    NotRequired,
    Required {
        policy: TrustPolicy,
        events: Vec<TrustEvent>,
    },
}

impl TrustDecision {
    #[must_use]
    pub fn policy(&self) -> Option<TrustPolicy> {
        match self {
            Self::NotRequired => None,
            Self::Required { policy, .. } => Some(*policy),
        }
    }

    #[must_use]
    pub fn events(&self) -> &[TrustEvent] {
        match self {
            Self::NotRequired => &[],
            Self::Required { events, .. } => events,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustResolver {
    config: TrustConfig,
}

impl TrustResolver {
    #[must_use]
    pub fn new(config: TrustConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn is_trust_prompt(screen_text: &str) -> bool {
        detect_trust_prompt(screen_text)
    }

    #[must_use]
    pub fn resolve(&self, cwd: &str) -> TrustDecision {
        self.resolve_with_text(cwd, "do you trust the files in this folder")
    }

    #[must_use]
    pub fn resolve_with_text(&self, cwd: &str, screen_text: &str) -> TrustDecision {
        if !detect_trust_prompt(screen_text) {
            return TrustDecision::NotRequired;
        }

        let mut events = vec![TrustEvent::TrustRequired { cwd: cwd.to_owned() }];

        if let Some(matched_root) =
            self.config.denied.iter().find(|root| path_matches(cwd, root))
        {
            let reason = format!("cwd matches denied trust root: {}", matched_root.display());
            events.push(TrustEvent::TrustDenied {
                cwd: cwd.to_owned(),
                reason,
            });
            return TrustDecision::Required {
                policy: TrustPolicy::Deny,
                events,
            };
        }

        if self.config.allowlisted.iter().any(|root| path_matches(cwd, root)) {
            events.push(TrustEvent::TrustResolved {
                cwd: cwd.to_owned(),
                policy: TrustPolicy::AutoTrust,
            });
            return TrustDecision::Required {
                policy: TrustPolicy::AutoTrust,
                events,
            };
        }

        TrustDecision::Required {
            policy: TrustPolicy::RequireApproval,
            events,
        }
    }

    #[must_use]
    pub fn trusts(&self, cwd: &str) -> bool {
        !self.config.denied.iter().any(|root| path_matches(cwd, root))
            && self.config.allowlisted.iter().any(|root| path_matches(cwd, root))
    }
}

/// Bridge: validate that a path is accessible given a trusted root and candidate path.
#[must_use]
pub fn validate_path_access(candidate: &str, trusted_root: &str) -> bool {
    path_matches_trusted_root(candidate, trusted_root)
}

#[must_use]
pub fn detect_trust_prompt(screen_text: &str) -> bool {
    let lowered = screen_text.to_ascii_lowercase();
    TRUST_PROMPT_CUES.iter().any(|needle| lowered.contains(needle))
}

#[must_use]
pub fn path_matches_trusted_root(cwd: &str, trusted_root: &str) -> bool {
    path_matches(cwd, &normalize_path(Path::new(trusted_root)))
}

fn path_matches(candidate: &str, root: &Path) -> bool {
    let candidate = normalize_path(Path::new(candidate));
    let root = normalize_path(root);
    candidate == root || candidate.starts_with(&root)
}

fn normalize_path(path: &Path) -> PathBuf {
    // Industrial Standard: Avoid relying solely on canonicalize() which fails if path doesn't exist.
    // We combine lexical normalization with canonicalization where possible.
    
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => {
                normalized.push(component);
            }
        }
    }

    if let Ok(canon) = std::fs::canonicalize(&normalized) {
        canon
    } else {
        normalized
    }
}
