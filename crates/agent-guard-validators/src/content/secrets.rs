//! Secret / credential detection over free text (S6-1 spike).
//!
//! Two complementary strategies:
//!
//! 1. **Named patterns** — high-precision regexes for well-known credential
//!    shapes (AWS keys, GitHub tokens, OpenAI keys, …). Low false-positive rate.
//! 2. **High-entropy fallback** — flags long, random-looking tokens that no
//!    named pattern caught. Higher recall, kept deliberately conservative so the
//!    spike stays usable.
//!
//! Findings never carry the raw secret: [`SecretFinding::preview`] is redacted
//! so results are safe to log or surface in an audit record.

use std::sync::OnceLock;

use regex::Regex;

use super::redact;

/// Minimum length for a token to be considered by the high-entropy fallback.
const ENTROPY_MIN_LEN: usize = 20;

/// Shannon-entropy threshold (bits per character) above which a token is
/// treated as random enough to be a secret. Random base64 sits near ~6.0,
/// hex near ~4.0; prose and identifiers sit well below.
const ENTROPY_THRESHOLD_BITS: f64 = 4.0;

/// Length at which a high-entropy token is flagged even without a digit, since
/// very long random-looking strings are credential-like regardless.
const ENTROPY_LONG_LEN: usize = 40;

/// The family of credential a [`SecretFinding`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    AwsAccessKeyId,
    GitHubToken,
    OpenAiKey,
    SlackToken,
    GoogleApiKey,
    StripeKey,
    PrivateKeyBlock,
    /// Caught by the entropy fallback, not a named pattern.
    HighEntropyString,
}

impl SecretKind {
    /// Short, stable human label used in redaction placeholders and reports.
    pub fn label(self) -> &'static str {
        match self {
            SecretKind::AwsAccessKeyId => "AWS Access Key",
            SecretKind::GitHubToken => "GitHub Token",
            SecretKind::OpenAiKey => "OpenAI Key",
            SecretKind::SlackToken => "Slack Token",
            SecretKind::GoogleApiKey => "Google API Key",
            SecretKind::StripeKey => "Stripe Key",
            SecretKind::PrivateKeyBlock => "Private Key",
            SecretKind::HighEntropyString => "High-Entropy Secret",
        }
    }
}

/// One detected secret. The byte range refers to `content` passed to [`scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFinding {
    pub kind: SecretKind,
    pub start: usize,
    pub end: usize,
    /// Redacted, log-safe representation of the match.
    pub preview: String,
}

/// Scan `content` for credentials and return findings ordered by position.
///
/// Named patterns take precedence; the entropy fallback only reports tokens
/// that do not overlap a named match.
pub fn scan(content: &str) -> Vec<SecretFinding> {
    let mut findings: Vec<SecretFinding> = Vec::new();

    for (kind, regex) in named_patterns() {
        for m in regex.find_iter(content) {
            findings.push(SecretFinding {
                kind: *kind,
                start: m.start(),
                end: m.end(),
                preview: redact(m.as_str()),
            });
        }
    }

    if let Some(token_regex) = token_regex() {
        for m in token_regex.find_iter(content) {
            if overlaps(&findings, m.start(), m.end()) {
                continue;
            }
            if is_high_entropy(m.as_str()) {
                findings.push(SecretFinding {
                    kind: SecretKind::HighEntropyString,
                    start: m.start(),
                    end: m.end(),
                    preview: redact(m.as_str()),
                });
            }
        }
    }

    findings.sort_by_key(|f| f.start);
    findings
}

/// True if `[start, end)` overlaps any already-recorded finding.
fn overlaps(findings: &[SecretFinding], start: usize, end: usize) -> bool {
    findings.iter().any(|f| start < f.end && f.start < end)
}

/// Conservative high-entropy test for the fallback path.
fn is_high_entropy(token: &str) -> bool {
    if token.len() < ENTROPY_MIN_LEN {
        return false;
    }
    if shannon_entropy(token) < ENTROPY_THRESHOLD_BITS {
        return false;
    }
    let has_digit = token.chars().any(|c| c.is_ascii_digit());
    let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
    // Require mixed alpha+digit, or sheer length, to avoid flagging long words.
    (has_digit && has_alpha) || token.len() >= ENTROPY_LONG_LEN
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Compiled named-credential patterns, built once.
fn named_patterns() -> &'static [(SecretKind, Regex)] {
    static PATTERNS: OnceLock<Vec<(SecretKind, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let raw: &[(SecretKind, &str)] = &[
            // AWS access key id: AKIA/ASIA + 16 uppercase alphanumerics.
            (SecretKind::AwsAccessKeyId, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            // GitHub PATs and OAuth/app tokens.
            (
                SecretKind::GitHubToken,
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b",
            ),
            // OpenAI keys, classic and project-scoped.
            (
                SecretKind::OpenAiKey,
                r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
            ),
            // Slack bot/user/app tokens.
            (SecretKind::SlackToken, r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
            // Google API key.
            (SecretKind::GoogleApiKey, r"\bAIza[0-9A-Za-z_-]{35}\b"),
            // Stripe secret / restricted live keys.
            (
                SecretKind::StripeKey,
                r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b",
            ),
            // PEM private-key header.
            (
                SecretKind::PrivateKeyBlock,
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            ),
        ];
        // Patterns are static literals validated by `all_named_patterns_compile`;
        // a compile failure drops only that one pattern rather than panicking.
        raw.iter()
            .filter_map(|(kind, pat)| Regex::new(pat).ok().map(|re| (*kind, re)))
            .collect()
    })
}

/// Tokeniser for the entropy fallback: credential-character runs.
///
/// Returns `None` only if the static literal fails to compile (guarded by a
/// test); the caller then skips the entropy strategy rather than panicking.
fn token_regex() -> Option<&'static Regex> {
    static TOKEN: OnceLock<Option<Regex>> = OnceLock::new();
    TOKEN
        .get_or_init(|| Regex::new(r"[A-Za-z0-9+/_=-]{20,}").ok())
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(content: &str) -> Vec<SecretKind> {
        scan(content).into_iter().map(|f| f.kind).collect()
    }

    #[test]
    fn detects_aws_access_key_id() {
        let found = scan("aws_key = AKIAIOSFODNN7EXAMPLE");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, SecretKind::AwsAccessKeyId);
    }

    #[test]
    fn detects_github_pat() {
        let token = format!("ghp_{}", "a".repeat(36));
        assert!(kinds(&format!("token: {token}")).contains(&SecretKind::GitHubToken));
    }

    #[test]
    fn detects_openai_key() {
        let key = format!("sk-{}", "Ab3xYz9Kqw".repeat(3));
        assert!(kinds(&format!("OPENAI_API_KEY={key}")).contains(&SecretKind::OpenAiKey));
    }

    #[test]
    fn detects_private_key_block() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        assert!(kinds(pem).contains(&SecretKind::PrivateKeyBlock));
    }

    #[test]
    fn finding_preview_is_redacted() {
        let found = scan("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(found[0].preview, "AKIA…(len 20)");
        // The raw secret must never appear in the preview.
        assert!(!found[0].preview.contains("IOSFODNN7EXAMPLE"));
    }

    #[test]
    fn high_entropy_fallback_flags_random_token() {
        // 40-char mixed base64-ish blob no named pattern claims.
        let blob = "Zk7Qp2Lm9Xt4Rv8Nw1Cb6Yd3Hs0Fg5Ja2Pe7Ui4";
        assert!(kinds(&format!("secret={blob}")).contains(&SecretKind::HighEntropyString));
    }

    #[test]
    fn ignores_ordinary_prose() {
        let prose = "The quick brown fox jumps over the lazy dog near the riverbank today.";
        assert!(scan(prose).is_empty());
    }

    #[test]
    fn ignores_normal_identifiers_and_paths() {
        let text = "let user_repository_factory = build();\n/usr/local/share/agent-guard/config";
        assert!(scan(text).is_empty());
    }

    #[test]
    fn empty_input_yields_no_findings() {
        assert!(scan("").is_empty());
    }

    #[test]
    fn all_named_patterns_compile() {
        // Guards the filter_map/.ok() fallback: every static literal must
        // actually compile, so none are silently dropped at runtime.
        assert_eq!(named_patterns().len(), 7);
        assert!(token_regex().is_some());
    }

    #[test]
    fn entropy_fallback_does_not_double_report_named_match() {
        // A GitHub token is also a long token; it must report once, as GitHub.
        let token = format!("ghp_{}", "b".repeat(36));
        let found = scan(&token);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, SecretKind::GitHubToken);
    }

    #[test]
    fn findings_are_ordered_by_position() {
        let token = format!("ghp_{}", "c".repeat(36));
        let content = format!("first AKIAIOSFODNN7EXAMPLE then {token}");
        let found = scan(&content);
        assert_eq!(found.len(), 2);
        assert!(found[0].start < found[1].start);
        assert_eq!(found[0].kind, SecretKind::AwsAccessKeyId);
        assert_eq!(found[1].kind, SecretKind::GitHubToken);
    }
}
