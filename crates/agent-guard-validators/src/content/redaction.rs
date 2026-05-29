//! Redaction modes for content findings (S6-3 spike).
//!
//! [`secrets`](super::secrets) and [`pii`](super::pii) say *what* sensitive
//! data is in a string and *where*. This module decides *what to do* about it,
//! turning spans into one of three enforcement actions:
//!
//! - [`RedactionMode::Block`] — signal the content must not be sent.
//! - [`RedactionMode::Mask`] — return a copy with each span replaced by a
//!   `[REDACTED:<label>]` placeholder.
//! - [`RedactionMode::Warn`] — leave content untouched, just report findings.
//!
//! Still off-by-default `content` feature; not wired into `Guard` yet (S6-4).

use super::pii::PiiFinding;
use super::secrets::SecretFinding;

/// What to do when sensitive content is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionMode {
    Block,
    Mask,
    Warn,
}

/// A detected sensitive region, detector-agnostic so secrets and PII can be
/// redacted in a single pass. Byte range refers to the scanned `content`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveSpan {
    pub start: usize,
    pub end: usize,
    /// Human label for the kind of data (e.g. `"Email"`, `"AWS Access Key"`).
    pub label: &'static str,
}

impl SensitiveSpan {
    pub fn from_secret(finding: &SecretFinding) -> Self {
        Self {
            start: finding.start,
            end: finding.end,
            label: finding.kind.label(),
        }
    }

    pub fn from_pii(finding: &PiiFinding) -> Self {
        Self {
            start: finding.start,
            end: finding.end,
            label: finding.kind.label(),
        }
    }
}

/// The result of applying a [`RedactionMode`] to some content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionOutcome {
    pub mode: RedactionMode,
    /// True only in [`RedactionMode::Block`] when at least one span was found.
    pub blocked: bool,
    /// Possibly-masked content. Equals the input for `Warn` and `Block`.
    pub content: String,
    /// The spans considered, ordered by position.
    pub spans: Vec<SensitiveSpan>,
}

/// Run both content detectors and return their spans merged and ordered.
///
/// Convenience entry point for the eventual `Guard` integration (S6-4).
pub fn scan_all(content: &str) -> Vec<SensitiveSpan> {
    let mut spans: Vec<SensitiveSpan> = Vec::new();
    spans.extend(
        super::secrets::scan(content)
            .iter()
            .map(SensitiveSpan::from_secret),
    );
    spans.extend(
        super::pii::scan(content)
            .iter()
            .map(SensitiveSpan::from_pii),
    );
    spans.sort_by_key(|s| s.start);
    spans
}

/// Apply `mode` to `content` given previously-detected `spans`.
pub fn redact_content(
    content: &str,
    spans: &[SensitiveSpan],
    mode: RedactionMode,
) -> RedactionOutcome {
    let mut ordered = spans.to_vec();
    ordered.sort_by_key(|s| s.start);

    let (blocked, new_content) = match mode {
        RedactionMode::Warn => (false, content.to_string()),
        RedactionMode::Block => (!ordered.is_empty(), content.to_string()),
        RedactionMode::Mask => (false, mask(content, &ordered)),
    };

    RedactionOutcome {
        mode,
        blocked,
        content: new_content,
        spans: ordered,
    }
}

/// Replace each (already position-ordered) span with a redaction placeholder.
///
/// Built left-to-right with safe slicing: spans overlapping an earlier one, or
/// not landing on UTF-8 boundaries, are skipped rather than panicking.
fn mask(content: &str, ordered_spans: &[SensitiveSpan]) -> String {
    let mut out = String::with_capacity(content.len());
    let mut cursor = 0usize;

    for span in ordered_spans {
        if span.start < cursor {
            continue;
        }
        let Some(prefix) = content.get(cursor..span.start) else {
            continue;
        };
        if content.get(span.start..span.end).is_none() {
            continue;
        }
        out.push_str(prefix);
        out.push_str(&format!("[REDACTED:{}]", span.label));
        cursor = span.end;
    }

    out.push_str(content.get(cursor..).unwrap_or(""));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize, label: &'static str) -> SensitiveSpan {
        SensitiveSpan { start, end, label }
    }

    #[test]
    fn warn_mode_leaves_content_unchanged() {
        let spans = [span(0, 4, "Email")];
        let out = redact_content("data here", &spans, RedactionMode::Warn);
        assert_eq!(out.content, "data here");
        assert!(!out.blocked);
        assert_eq!(out.spans.len(), 1);
    }

    #[test]
    fn block_mode_flags_blocked_when_findings_present() {
        let spans = [span(0, 4, "Email")];
        let out = redact_content("data here", &spans, RedactionMode::Block);
        assert!(out.blocked);
        assert_eq!(out.content, "data here");
    }

    #[test]
    fn block_mode_not_blocked_when_clean() {
        let out = redact_content("nothing sensitive", &[], RedactionMode::Block);
        assert!(!out.blocked);
    }

    #[test]
    fn mask_mode_replaces_span_with_placeholder() {
        // "mail a@b.co x": email occupies bytes 5..11.
        let content = "mail a@b.co x";
        let spans = [span(5, 11, "Email")];
        let out = redact_content(content, &spans, RedactionMode::Mask);
        assert_eq!(out.content, "mail [REDACTED:Email] x");
        assert!(!out.blocked);
    }

    #[test]
    fn mask_mode_handles_multiple_spans() {
        let content = "a@b.co and c@d.co";
        let spans = [span(0, 6, "Email"), span(11, 17, "Email")];
        let out = redact_content(content, &spans, RedactionMode::Mask);
        assert_eq!(out.content, "[REDACTED:Email] and [REDACTED:Email]");
    }

    #[test]
    fn mask_skips_overlapping_span() {
        let content = "0123456789";
        // Second span overlaps the first; only the first should apply.
        let spans = [span(0, 5, "A"), span(3, 8, "B")];
        let out = redact_content(content, &spans, RedactionMode::Mask);
        assert_eq!(out.content, "[REDACTED:A]56789");
    }

    #[test]
    fn mask_with_no_spans_returns_original() {
        let out = redact_content("untouched", &[], RedactionMode::Mask);
        assert_eq!(out.content, "untouched");
    }

    #[test]
    fn mask_ignores_out_of_range_span() {
        let content = "short";
        let spans = [span(2, 99, "X")];
        let out = redact_content(content, &spans, RedactionMode::Mask);
        // Out-of-range span is skipped; content is preserved.
        assert_eq!(out.content, "short");
    }

    #[test]
    fn scan_all_merges_secrets_and_pii_in_order() {
        let content = "key AKIAIOSFODNN7EXAMPLE mail a@b.co";
        let spans = scan_all(content);
        let labels: Vec<&str> = spans.iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["AWS Access Key", "Email"]);
        assert!(spans[0].start < spans[1].start);
    }

    #[test]
    fn mask_end_to_end_via_scan_all() {
        let content = "card 4111111111111111 stored";
        let spans = scan_all(content);
        let out = redact_content(content, &spans, RedactionMode::Mask);
        assert_eq!(out.content, "card [REDACTED:Credit Card] stored");
    }
}
