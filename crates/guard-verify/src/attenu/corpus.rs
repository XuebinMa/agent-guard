//! Scoring against the published interoperability corpus.
//!
//! The corpus scores a bundle verifier by a minimal-set rule: each rejecting
//! case declares the failures that MUST appear, with their exact reason and
//! exact position. A conformant verifier may report more — one broken record
//! often makes a second check unsatisfiable — but never fewer, and never at a
//! different position.

use super::{verify_bundle, BundleReport, Failure, Signer};
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
