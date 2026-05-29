//! Personal-data (PII) detection over free text (S6-2 spike).
//!
//! Companion to [`super::secrets`]: where that module flags credentials, this
//! one flags personal data an agent might leak to an LLM provider or outbound
//! call — the boundary GDPR / EU AI Act obligations attach to.
//!
//! Detected today: email addresses, US SSNs, payment-card numbers
//! (Luhn-validated to cut false positives), and formatted phone numbers.
//!
//! Findings never carry the raw value: [`PiiFinding::preview`] is redacted via
//! the shared [`super::redact`] so results are safe to log.

use std::sync::OnceLock;

use regex::Regex;

use super::redact;

/// Payment-card numbers are 13–19 digits once separators are stripped.
const CARD_MIN_DIGITS: usize = 13;
const CARD_MAX_DIGITS: usize = 19;

/// The kind of personal data a [`PiiFinding`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiKind {
    Email,
    UsSsn,
    CreditCard,
    PhoneNumber,
}

impl PiiKind {
    /// Short, stable human label used in redaction placeholders and reports.
    pub fn label(self) -> &'static str {
        match self {
            PiiKind::Email => "Email",
            PiiKind::UsSsn => "US SSN",
            PiiKind::CreditCard => "Credit Card",
            PiiKind::PhoneNumber => "Phone Number",
        }
    }
}

/// One detected PII value. The byte range refers to `content` passed to [`scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiFinding {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    /// Redacted, log-safe representation of the match.
    pub preview: String,
}

/// Scan `content` for personal data and return findings ordered by position.
///
/// Detection runs most-specific first (cards, then email/SSN, then the
/// false-positive-prone phone pattern); later strategies skip any span an
/// earlier one already claimed.
pub fn scan(content: &str) -> Vec<PiiFinding> {
    let mut findings: Vec<PiiFinding> = Vec::new();

    // Payment cards: regex finds candidates, Luhn confirms them.
    if let Some(card_regex) = card_regex() {
        for m in card_regex.find_iter(content) {
            let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
            if luhn_valid(&digits) {
                findings.push(finding(PiiKind::CreditCard, &m));
            }
        }
    }

    for (kind, regex) in named_patterns() {
        for m in regex.find_iter(content) {
            if overlaps(&findings, m.start(), m.end()) {
                continue;
            }
            findings.push(finding(*kind, &m));
        }
    }

    if let Some(phone_regex) = phone_regex() {
        for m in phone_regex.find_iter(content) {
            if overlaps(&findings, m.start(), m.end()) {
                continue;
            }
            findings.push(finding(PiiKind::PhoneNumber, &m));
        }
    }

    findings.sort_by_key(|f| f.start);
    findings
}

fn finding(kind: PiiKind, m: &regex::Match<'_>) -> PiiFinding {
    PiiFinding {
        kind,
        start: m.start(),
        end: m.end(),
        preview: redact(m.as_str()),
    }
}

/// True if `[start, end)` overlaps any already-recorded finding.
fn overlaps(findings: &[PiiFinding], start: usize, end: usize) -> bool {
    findings.iter().any(|f| start < f.end && f.start < end)
}

/// Luhn checksum over the digits of a candidate card number.
fn luhn_valid(digits: &str) -> bool {
    let values: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if values.len() < CARD_MIN_DIGITS || values.len() > CARD_MAX_DIGITS {
        return false;
    }
    let sum: u32 = values
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Compiled email and SSN patterns, built once.
fn named_patterns() -> &'static [(PiiKind, Regex)] {
    static PATTERNS: OnceLock<Vec<(PiiKind, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let raw: &[(PiiKind, &str)] = &[
            (
                PiiKind::Email,
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            ),
            // US Social Security Number, hyphenated form only (precision over recall).
            (PiiKind::UsSsn, r"\b\d{3}-\d{2}-\d{4}\b"),
        ];
        // Static literals are guarded by `all_patterns_compile`; a failure drops
        // only that one pattern rather than panicking.
        raw.iter()
            .filter_map(|(kind, pat)| Regex::new(pat).ok().map(|re| (*kind, re)))
            .collect()
    })
}

/// Candidate payment-card matcher (13–19 digits with optional single separators).
fn card_regex() -> Option<&'static Regex> {
    static CARD: OnceLock<Option<Regex>> = OnceLock::new();
    CARD.get_or_init(|| Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").ok())
        .as_ref()
}

/// Formatted phone numbers: separated NANP groups, or E.164 with country code.
///
/// Requiring separators (or a leading `+`) keeps plain digit runs from being
/// misread as phone numbers.
fn phone_regex() -> Option<&'static Regex> {
    static PHONE: OnceLock<Option<Regex>> = OnceLock::new();
    PHONE
        .get_or_init(|| {
            Regex::new(r"(?:\+\d{1,3}[ -]?)?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}\b|\+\d{8,15}\b").ok()
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(content: &str) -> Vec<PiiKind> {
        scan(content).into_iter().map(|f| f.kind).collect()
    }

    #[test]
    fn detects_email() {
        let found = scan("reach john.doe@example.com please");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_us_ssn() {
        assert!(kinds("SSN: 123-45-6789 on file").contains(&PiiKind::UsSsn));
    }

    #[test]
    fn detects_credit_card_passing_luhn() {
        // 4111 1111 1111 1111 is a standard Luhn-valid Visa test number.
        assert!(kinds("card 4111111111111111 charged").contains(&PiiKind::CreditCard));
    }

    #[test]
    fn ignores_card_like_number_failing_luhn() {
        // Same number, last digit changed — fails Luhn, so not a card. Nothing
        // else in the PII set claims a bare 16-digit run, so no findings.
        assert!(scan("ref 4111111111111112 logged").is_empty());
    }

    #[test]
    fn detects_phone_number() {
        assert!(kinds("call 415-555-2671 tomorrow").contains(&PiiKind::PhoneNumber));
    }

    #[test]
    fn finding_preview_is_redacted() {
        let found = scan("john.doe@example.com");
        assert_eq!(found[0].preview, "john…(len 20)");
        assert!(!found[0].preview.contains("example.com"));
    }

    #[test]
    fn ignores_ordinary_prose() {
        let prose = "The meeting is at noon and there are about 200 attendees expected.";
        assert!(scan(prose).is_empty());
    }

    #[test]
    fn empty_input_yields_no_findings() {
        assert!(scan("").is_empty());
    }

    #[test]
    fn findings_are_ordered_by_position() {
        let content = "ssn 123-45-6789 and mail a@b.co here";
        let found = scan(content);
        assert_eq!(found.len(), 2);
        assert!(found[0].start < found[1].start);
        assert_eq!(found[0].kind, PiiKind::UsSsn);
        assert_eq!(found[1].kind, PiiKind::Email);
    }

    #[test]
    fn all_patterns_compile() {
        assert_eq!(named_patterns().len(), 2);
        assert!(card_regex().is_some());
        assert!(phone_regex().is_some());
    }
}
