//! Corpus matching is narrower than the verifier's diagnostic equality.

use super::*;
use crate::attenu::test_support::published;

fn malformed_case() -> VectorCase {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"].as_array_mut().unwrap().push(Value::Null);
    VectorCase {
        name: "indexed_failure".to_string(),
        signer,
        bundle,
        expect: "reject".to_string(),
        expect_failures: vec![Failure::chain_level("invalid_ledger_entry")],
        expect_report: BTreeMap::new(),
    }
}

fn envelope_case(case: &VectorCase) -> EnvelopeVectorCase {
    EnvelopeVectorCase {
        name: case.name.clone(),
        signer: Some(case.signer.clone()),
        witness_keys: Vec::new(),
        bundle: case.bundle.clone(),
        expect: case.expect.clone(),
        expect_states: BTreeMap::new(),
        expect_failures: case.expect_failures.clone(),
        canonical_hex: None,
        raw_hex: None,
    }
}

/// Both scorers match the published triple without removing local diagnostics.
#[test]
fn indexed_diagnostics_match_the_published_failure_triple() {
    let case = malformed_case();
    let bundle = score_case(&case);
    let envelope = score_envelope_case(&envelope_case(&case));
    for (conformant, problems, report) in [
        (bundle.conformant, bundle.problems, bundle.report),
        (envelope.conformant, envelope.problems, envelope.report),
    ] {
        assert!(conformant, "{problems:?}");
        assert!(!report.accepted, "the malformed bundle is still rejected");
        assert!(report.failures.iter().any(|failure| {
            failure.reason == "invalid_ledger_entry" && failure.entry_index.is_some()
        }));
    }
}

#[test]
fn a_required_indexed_diagnostic_is_not_also_additional() {
    let case = malformed_case();
    for additional in [
        score_case(&case).additional,
        score_envelope_case(&envelope_case(&case)).additional,
    ] {
        assert!(additional
            .iter()
            .all(|failure| failure.reason != "invalid_ledger_entry"));
        assert!(!additional.is_empty(), "genuinely additional findings remain");
    }
}

/// Null position members are exact values, not wildcards for entry positions.
#[test]
fn each_published_failure_member_must_match_exactly() {
    let (bundle, signer) = published("reject_params_mismatch");
    let placed = verify_bundle(&bundle, &signer)
        .failures
        .into_iter()
        .find(|failure| failure.reason == "params_mismatch")
        .unwrap();
    assert!(placed.seq.is_some() && placed.node.is_some());
    for use_placed in [false, true] {
        for member in ["reason", "seq", "node"] {
            let mut case = malformed_case();
            if use_placed {
                case.bundle = bundle.clone();
                case.signer = signer.clone();
                case.expect_failures = vec![placed.clone()];
            }
            let required = &mut case.expect_failures[0];
            match member {
                "reason" => required.reason.push_str("_not_the_required_reason"),
                "seq" => required.seq = if use_placed { None } else { Some(7) },
                "node" => {
                    required.node = if use_placed {
                        None
                    } else {
                        Some("vectors:n0".to_string())
                    }
                }
                _ => unreachable!(),
            }
            assert!(!score_case(&case).conformant, "bundle {member}");
            assert!(
                !score_envelope_case(&envelope_case(&case)).conformant,
                "envelope {member}"
            );
        }
    }
}

#[test]
fn diagnostic_equality_remains_strict_outside_corpus_scoring() {
    let indexed = Failure::indexed(7, "invalid_ledger_entry");
    let unindexed = Failure::chain_level("invalid_ledger_entry");
    assert_ne!(indexed, unindexed);
    assert_eq!(serde_json::to_value(indexed).unwrap()["entry_index"], 7);
}

#[test]
fn verdict_mismatches_still_fail_both_corpus_scorers() {
    let mut case = malformed_case();
    case.expect = "accept".to_string();
    assert!(!score_case(&case).conformant);
    assert!(!score_envelope_case(&envelope_case(&case)).conformant);
}
