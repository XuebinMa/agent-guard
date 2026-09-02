use super::corpus::{score_corpus, VectorFile};
use super::*;
use sha2::{Digest, Sha256};

const CORPUS: &str = include_str!("../../fixtures/attenu/bundle_vectors_v1.json");

fn corpus() -> VectorFile {
    serde_json::from_str(CORPUS).expect("corpus parses")
}

/// The corpus is evidence only while the bytes are the published ones. This
/// pins the hash the upstream release and an independent third party both
/// state, so a silent edit to the fixture fails here rather than turning the
/// conformance result into a claim about our own copy.
#[test]
fn attenu_corpus_fixture_bytes_are_pinned() {
    let digest = Sha256::digest(CORPUS.as_bytes());
    assert_eq!(
        hex::encode(digest),
        "90d7fa70eabe92cbfa4df04bad50ac78995b57e83812cc5671e1ba9de01619ce"
    );
    assert_eq!(CORPUS.len(), 69_573);
}

#[test]
fn attenu_corpus_version_is_the_one_we_implement() {
    assert_eq!(corpus().version, "bundle_vectors_v1");
}

/// Every case scores: acceptance matches, and each required failure appears
/// with its exact reason at its exact position.
#[test]
fn attenu_bundle_corpus_scores_conformant() {
    let file = corpus();
    assert_eq!(file.cases.len(), 8);

    let scores = score_corpus(&file);
    let failed: Vec<String> = scores
        .iter()
        .filter(|score| !score.conformant)
        .map(|score| format!("{}: {}", score.name, score.problems.join("; ")))
        .collect();

    assert!(failed.is_empty(), "non-conformant cases: {failed:?}");
}

/// The accepting case must be accepted with no failures at all, which is the
/// half of conformance a verifier that rejects everything would pass.
#[test]
fn attenu_valid_bundle_is_accepted_cleanly() {
    let file = corpus();
    let case = file
        .cases
        .iter()
        .find(|case| case.name == "valid_bundle_v2")
        .expect("valid case present");

    let report = verify_bundle(&case.bundle, &case.signer);
    assert!(report.accepted, "failures: {:?}", report.failures);
    assert!(report.failures.is_empty());
    assert!(report.unaccounted_calls.is_empty());
}

/// A rewritten ledger is self-consistent, so the anchor is the only thing
/// that catches it. Guard against an implementation that checks the chain and
/// calls it done.
#[test]
fn attenu_rehashed_chain_is_caught_only_by_the_anchor() {
    let file = corpus();
    let case = file
        .cases
        .iter()
        .find(|case| case.name == "reject_rehashed_chain")
        .expect("rehashed case present");

    let report = verify_bundle(&case.bundle, &case.signer);
    assert!(!report.accepted);
    assert!(report
        .failures
        .iter()
        .any(|failure| failure.reason == "integrity(anchor)"
            && failure.seq.is_none()
            && failure.node.is_none()));
    assert!(
        !report.failures.iter().any(|f| f.reason == "integrity"),
        "the chain reproduces from genesis; only the anchor should fail"
    );
}

/// The anchor carries `verified: true` in every case. It is the producer's
/// claim about itself, and reading it instead of re-checking would accept a
/// rewritten ledger.
#[test]
fn attenu_producer_self_report_is_not_trusted() {
    let file = corpus();
    let case = file
        .cases
        .iter()
        .find(|case| case.name == "reject_rehashed_chain")
        .expect("rehashed case present");

    assert_eq!(
        case.bundle
            .get("anchor")
            .and_then(|anchor| anchor.get("verified")),
        Some(&serde_json::Value::Bool(true))
    );
    assert!(!verify_bundle(&case.bundle, &case.signer).accepted);
}

/// An outcome whose call was never authorized leaves the real call
/// unobserved. That is reported as an aggregate, not as a rule violation.
#[test]
fn attenu_unaccounted_calls_are_reported_without_inventing_a_failure() {
    let file = corpus();
    let case = file
        .cases
        .iter()
        .find(|case| case.name == "reject_outcome_without_allow")
        .expect("orphan case present");

    let report = verify_bundle(&case.bundle, &case.signer);
    assert_eq!(report.unaccounted_calls.len(), 1);
    assert!(report
        .failures
        .iter()
        .all(|failure| failure.reason != "allow_without_outcome"));
}

#[test]
fn jcs_sorts_object_keys_and_escapes_minimally() {
    let value = serde_json::json!({"b": 1, "a": "x\"y", "c": [1, 2]});
    let canonical = crate::jcs::canonicalize(&value).expect("canonicalizes");
    assert_eq!(
        String::from_utf8(canonical).unwrap(),
        r#"{"a":"x\"y","b":1,"c":[1,2]}"#
    );
}

#[test]
fn jcs_refuses_non_integer_numbers_instead_of_guessing() {
    let value = serde_json::json!({"n": 1.5});
    assert!(crate::jcs::canonicalize(&value).is_err());
}
