//! Content-layer validation (S6-1 secrets, S6-2 PII).
//!
//! Where `bash` and `path` guard the *action* an agent is about to take, this
//! module inspects the *content* an agent is about to emit — the second half of
//! agent-guard's two-layer outbound model. The proof points are detecting
//! credentials/secrets ([`secrets`]) and personal data ([`pii`]) in text before
//! it leaves for an LLM provider or a mutation HTTP call.
//!
//! This is a feasibility PoC: it is gated behind the off-by-default `content`
//! feature and is intentionally *not* wired into the `Guard` pipeline yet.

pub mod pii;
pub mod redaction;
pub mod secrets;

pub use pii::{scan as scan_pii, PiiFinding, PiiKind};
pub use redaction::{redact_content, scan_all, RedactionMode, RedactionOutcome, SensitiveSpan};
pub use secrets::{scan as scan_secrets, SecretFinding, SecretKind};

/// How many leading characters of a sensitive match are kept in a redacted
/// preview. Enough to recognise the value's shape, not enough to recover it.
const PREVIEW_PREFIX_LEN: usize = 4;

/// Redact a sensitive value to a recognisable but unusable preview, e.g.
/// `AKIA…(len 20)`. Shared by both content detectors so findings are always
/// safe to log or surface in an audit record.
pub(crate) fn redact(value: &str) -> String {
    let prefix: String = value.chars().take(PREVIEW_PREFIX_LEN).collect();
    format!("{prefix}…(len {})", value.chars().count())
}
