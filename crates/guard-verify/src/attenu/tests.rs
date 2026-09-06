use super::corpus::{score_corpus, score_envelope_corpus, EnvelopeVectorFile, VectorFile};
use super::envelope::EntryWitness;
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
        "54311d68c8342c01ce233f4b1aea251125a4f3323fd9776c01843d3b2f5700ea"
    );
    assert_eq!(CORPUS.len(), 146_765);
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
    assert_eq!(file.cases.len(), 17);

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

/// Delegation containment fails on four separate dimensions, and a verifier
/// that checks only the obvious one passes the others silently.
///
/// This is not hypothetical: the reference implementation accepted a child
/// whose scopes were a literal subset of its parent's but which took a longer
/// ttl, a looser ceiling, no ceiling, or no ttl — its monotonicity check was
/// gated on a literal scope difference. Until the corpus grew these rows this
/// path here had no negative coverage either, so it passed for the same
/// reason: nothing attacked it.
#[test]
fn attenu_containment_is_checked_on_every_dimension() {
    let file = corpus();

    for (case_name, reason) in [
        ("reject_widened_scope", "monotonicity"),
        ("reject_increased_ttl", "monotonicity"),
        ("reject_loosened_ceiling", "monotonicity"),
        // The `_literal` rows keep the scope set a literal subset, so only the
        // named dimension can be what fails.
        ("reject_increased_ttl_literal", "monotonicity"),
        ("reject_loosened_ceiling_literal", "monotonicity"),
        ("reject_null_ttl_literal", "monotonicity"),
        ("reject_omitted_ceiling_literal", "monotonicity"),
        // Allow-level: authorizing outside what this node was granted.
        ("reject_uncontained_allow", "containment"),
    ] {
        let case = file
            .cases
            .iter()
            .find(|case| case.name == case_name)
            .unwrap_or_else(|| panic!("{case_name} missing from the corpus"));

        let report = verify_bundle(&case.bundle, &case.signer);
        assert!(!report.accepted, "{case_name} must be rejected");
        assert!(
            report.failures.iter().any(|f| f.reason == reason),
            "{case_name} must fail as {reason}, got {:?}",
            report.failures
        );
    }
}

const ENVELOPE_CORPUS: &str = include_str!("../../fixtures/attenu/envelope_vectors_v1.json");

fn envelope_corpus() -> EnvelopeVectorFile {
    serde_json::from_str(ENVELOPE_CORPUS).expect("envelope corpus parses")
}

/// Same reasoning as the bundle fixture: a conformance result is a claim about
/// the published bytes, so a silent edit has to fail here rather than quietly
/// become a claim about our own copy. This hash is the one attenu-guard
/// published and a second independent runner reported.
#[test]
fn attenu_envelope_fixture_bytes_are_pinned() {
    let digest = Sha256::digest(ENVELOPE_CORPUS.as_bytes());
    assert_eq!(
        hex::encode(digest),
        "6a57d75ebec881d39d5a1805793a20f9a6d7bff021b70782dcb57c43b276df64"
    );
    assert_eq!(ENVELOPE_CORPUS.len(), 185_227);
}

#[test]
fn attenu_envelope_corpus_version_is_the_one_we_implement() {
    let file = envelope_corpus();
    assert_eq!(file.version, "envelope_vectors_v1");
    assert_eq!(file.revision.as_deref(), Some("envelope_vectors_v1.1"));
}

/// Every case scores: acceptance matches, every entry's state matches, and
/// each required failure appears with its exact reason at its exact position.
#[test]
fn attenu_envelope_corpus_scores_conformant() {
    let file = envelope_corpus();
    assert_eq!(file.cases.len(), 18);

    let scores = score_envelope_corpus(&file);
    let failed: Vec<String> = scores
        .iter()
        .filter(|score| !score.conformant)
        .map(|score| format!("{}: {}", score.name, score.problems.join("; ")))
        .collect();

    assert!(failed.is_empty(), "non-conformant cases: {failed:?}");
}

/// An absent envelope is the status quo, not a downgrade: a bundle written
/// before this contract existed still verifies, and every entry reports
/// `process-asserted` rather than the verifier inventing a finding.
#[test]
fn attenu_absent_envelopes_leave_the_bundle_exactly_as_it_was() {
    let file = envelope_corpus();
    let case = file
        .cases
        .iter()
        .find(|case| case.name == "absent_envelope")
        .expect("case present");
    assert!(case.bundle.get("envelopes").is_none());

    let scores = score_envelope_corpus(&file);
    let score = scores
        .iter()
        .find(|score| score.name == "absent_envelope")
        .expect("scored");

    assert!(score.report.accepted);
    assert!(score.report.failures.is_empty());
    let envelopes = score.report.envelopes.as_ref().expect("states reported");
    assert!(envelopes
        .states
        .iter()
        .all(|state| matches!(state, EntryWitness::ProcessAsserted)));
}

/// Two honest envelopes over one entry are a contradiction by construction,
/// so the entry stops being witness-signed. Without this, whichever envelope
/// was read last would decide the state and the same bundle in the other
/// array order would score differently.
#[test]
fn attenu_a_second_envelope_over_one_entry_forfeits_the_entry() {
    let file = envelope_corpus();
    let scores = score_envelope_corpus(&file);
    let score = scores
        .iter()
        .find(|score| score.name == "reject_duplicate_subject")
        .expect("scored");

    assert!(!score.report.accepted);
    let envelopes = score.report.envelopes.as_ref().expect("states reported");
    assert_eq!(
        envelopes.states[1],
        EntryWitness::ProcessAsserted,
        "the covered entry must not keep the first envelope's state"
    );
}

/// The subject's `entry_hash` is recomputed from the bundle, never read from
/// beside it. `reject_masked_bundle_mutation` is the row that separates the
/// two: the ledger was rewritten consistently and re-anchored, so every
/// chain-level check passes and only the envelope disagrees.
#[test]
fn attenu_envelope_binds_to_a_recomputed_hash_not_a_stored_one() {
    let file = envelope_corpus();
    let scores = score_envelope_corpus(&file);
    let score = scores
        .iter()
        .find(|score| score.name == "reject_masked_bundle_mutation")
        .expect("scored");

    assert!(!score.report.accepted);
    assert!(
        score
            .report
            .failures
            .iter()
            .all(|failure| failure.reason == "envelope_subject_mismatch"),
        "nothing at chain level may be reported here: {:?}",
        score.report.failures
    );
}
