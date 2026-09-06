//! Scoring against the published interoperability corpus.
//!
//! The corpus scores a bundle verifier by a minimal-set rule: each rejecting
//! case declares the failures that MUST appear, with their exact reason and
//! exact position. A conformant verifier may report more — one broken record
//! often makes a second check unsatisfiable — but never fewer, and never at a
//! different position.

use std::collections::{BTreeMap, HashMap};

use super::{
    verify_bundle, verify_bundle_with_envelopes, BundleReport, Failure, Signer, TrustSet,
    WitnessKey,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct VectorCase {
    pub name: String,
    pub signer: Signer,
    pub bundle: Value,
    pub expect: String,
    #[serde(default)]
    pub expect_failures: Vec<Failure>,
}

#[derive(Debug, Deserialize)]
pub struct VectorFile {
    pub version: String,
    pub cases: Vec<VectorCase>,
}

#[derive(Debug)]
pub struct CaseScore {
    pub name: String,
    pub conformant: bool,
    /// Why the case did not score, empty when it did.
    pub problems: Vec<String>,
    /// Failures reported beyond the required minimal set. Permitted, and
    /// worth surfacing so a diagnostic difference stays visible.
    pub additional: Vec<Failure>,
    pub report: BundleReport,
}

/// Score every case in the corpus.
pub fn score_corpus(file: &VectorFile) -> Vec<CaseScore> {
    file.cases.iter().map(score_case).collect()
}

fn score_case(case: &VectorCase) -> CaseScore {
    let report = verify_bundle(&case.bundle, &case.signer);
    let should_accept = case.expect == "accept";
    let mut problems = Vec::new();

    if report.accepted != should_accept {
        problems.push(format!(
            "expected {}, verifier {}",
            case.expect,
            if report.accepted {
                "accepted"
            } else {
                "rejected"
            }
        ));
    }

    for required in &case.expect_failures {
        if !report.failures.contains(required) {
            problems.push(format!(
                "missing required failure {} at seq {:?} node {:?}",
                required.reason, required.seq, required.node
            ));
        }
    }

    let additional = report
        .failures
        .iter()
        .filter(|failure| !case.expect_failures.contains(failure))
        .cloned()
        .collect();

    CaseScore {
        name: case.name.clone(),
        conformant: problems.is_empty(),
        problems,
        additional,
        report,
    }
}

/// One observer-envelope case.
///
/// `signer` is nullable: one case carries no anchor at all, and an absent
/// anchor is not an envelope failure. `expect_states` asserts a state for
/// **every** entry, not only the covered ones, so an accepting case asserts
/// what is true rather than merely the absence of a failure.
#[derive(Debug, Deserialize)]
pub struct EnvelopeVectorCase {
    pub name: String,
    #[serde(default)]
    pub signer: Option<Signer>,
    #[serde(default)]
    pub witness_keys: Vec<WitnessKey>,
    pub bundle: Value,
    pub expect: String,
    #[serde(default)]
    pub expect_states: BTreeMap<String, String>,
    #[serde(default)]
    pub expect_failures: Vec<Failure>,
    /// The exact JCS bytes the signature covers, on the canonicalization
    /// positive control. Scored on both halves: it accepts, *and* the bytes
    /// this verifier canonicalized are these.
    #[serde(default)]
    pub canonical_hex: Option<String>,
    /// The envelope bytes as received, for the one case whose failure cannot
    /// be raised from a parsed object.
    #[serde(default)]
    pub raw_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnvelopeVectorFile {
    pub version: String,
    #[serde(default)]
    pub revision: Option<String>,
    pub cases: Vec<EnvelopeVectorCase>,
}

#[derive(Debug)]
pub struct EnvelopeCaseScore {
    pub name: String,
    pub conformant: bool,
    pub problems: Vec<String>,
    pub additional: Vec<Failure>,
    pub report: BundleReport,
}

/// Score every case in the observer-envelope corpus.
pub fn score_envelope_corpus(file: &EnvelopeVectorFile) -> Vec<EnvelopeCaseScore> {
    file.cases.iter().map(score_envelope_case).collect()
}

fn score_envelope_case(case: &EnvelopeVectorCase) -> EnvelopeCaseScore {
    let mut problems = Vec::new();

    let trust = match TrustSet::build(&case.witness_keys) {
        Ok(trust) => trust,
        Err(error) => {
            // Deployment configuration, not a bundle finding: there is nothing
            // to score, and saying so beats scoring the case as a failure of
            // the verifier.
            return EnvelopeCaseScore {
                name: case.name.clone(),
                conformant: false,
                problems: vec![format!("unusable trust set: {error}")],
                additional: Vec::new(),
                report: BundleReport {
                    accepted: false,
                    failures: Vec::new(),
                    unaccounted_calls: Vec::new(),
                    envelopes: None,
                },
            };
        }
    };

    let mut received = HashMap::new();
    if let Some(raw_hex) = &case.raw_hex {
        match hex::decode(raw_hex) {
            // The corpus carries the bytes for that case's single envelope.
            Ok(bytes) => {
                received.insert(0usize, bytes);
            }
            Err(error) => problems.push(format!("raw_hex is not hex: {error}")),
        }
    }

    let report =
        verify_bundle_with_envelopes(&case.bundle, case.signer.as_ref(), &trust, &received);
    let should_accept = case.expect == "accept";

    if report.accepted != should_accept {
        problems.push(format!(
            "expected {}, verifier {}",
            case.expect,
            if report.accepted {
                "accepted"
            } else {
                "rejected"
            }
        ));
    }

    match &report.envelopes {
        None => problems.push("verifier reported no envelope states".to_string()),
        Some(envelopes) => {
            for (index, expected) in &case.expect_states {
                let Ok(index) = index.parse::<usize>() else {
                    problems.push(format!("unreadable expect_states key {index}"));
                    continue;
                };
                match envelopes.states.get(index) {
                    Some(actual) if actual.state() == expected => {}
                    Some(actual) => problems.push(format!(
                        "entry {index}: expected {expected}, got {}",
                        actual.state()
                    )),
                    None => problems.push(format!("entry {index}: no state reported")),
                }
            }

            if let Some(canonical_hex) = &case.canonical_hex {
                match envelopes.canonical.first().and_then(Option::as_ref) {
                    Some(actual) if hex::encode(actual) == *canonical_hex => {}
                    Some(actual) => problems.push(format!(
                        "canonical bytes differ: got {}",
                        hex::encode(actual)
                    )),
                    None => problems.push("no canonical bytes produced".to_string()),
                }
            }
        }
    }

    for required in &case.expect_failures {
        if !report.failures.contains(required) {
            problems.push(format!(
                "missing required failure {} at seq {:?} node {:?}",
                required.reason, required.seq, required.node
            ));
        }
    }

    let additional = report
        .failures
        .iter()
        .filter(|failure| !case.expect_failures.contains(failure))
        .cloned()
        .collect();

    EnvelopeCaseScore {
        name: case.name.clone(),
        conformant: problems.is_empty(),
        problems,
        additional,
        report,
    }
}
