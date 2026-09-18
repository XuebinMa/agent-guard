//! Version dispatch, pinned before the corpus has a row that reaches it.
//!
//! Every bundle in `bundle_vectors_v1.4` is a `schema_version=2` chain, so no
//! published row exercises a v1 ledger (a2aproject/A2A#1575, 2026-09-17). The
//! rules tested here come from the corpus README's reason table and its
//! "version-independent" paragraph, never from an implementation.
//!
//! The v1 bundles are derived here by changing `v` and re-sealing a published
//! v2 case. They are this verifier's reading of the format, not the upcoming
//! `reject_unknown_policy_value_v1_chain` row: the README does not yet say
//! which entry fields are v2-only, so "the canonical v1 form" is not defined
//! anywhere a third party can read, and these cases keep every field.

use super::corpus::VectorFile;
use super::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const CORPUS: &str = include_str!("../../fixtures/attenu/bundle_vectors_v1.json");
const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn published(name: &str) -> (Value, Signer) {
    let file: VectorFile = serde_json::from_str(CORPUS).expect("corpus parses");
    let case = file
        .cases
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("case {name} present"));
    (case.bundle, case.signer)
}

/// Recompute every entry hash and re-sign the anchor over the new head, so a
/// derived bundle fails only for the rule under test and never for integrity.
fn reseal(bundle: &mut Value, signer: &Signer) {
    let mut prev = GENESIS_PREV.to_string();
    let mut last_seq = 0;
    let entries = bundle["entries"].as_array_mut().expect("entries");
    for entry in entries.iter_mut() {
        entry["prev_hash"] = Value::String(prev.clone());
        let mut body = entry.clone();
        body.as_object_mut().expect("entry object").remove("hash");
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(crate::jcs::canonicalize(&body).expect("entry canonicalizes"));
        prev = hex::encode(hasher.finalize());
        entry["hash"] = Value::String(prev.clone());
        last_seq = entry["seq"].as_i64().expect("seq");
    }

    let anchor = &mut bundle["anchor"];
    anchor["head"] = Value::String(prev);
    anchor["seq"] = Value::from(last_seq);
    let mut body = anchor.clone();
    let map = body.as_object_mut().expect("anchor object");
    for member in ["kid", "sig", "verified"] {
        map.remove(member);
    }
    let secret = hex::decode(&signer.secret_hex).expect("secret hex");
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("hmac key");
    mac.update(&crate::jcs::canonicalize(&body).expect("anchor canonicalizes"));
    anchor["sig"] = Value::String(hex::encode(mac.finalize().into_bytes()));
}

/// The same ledger declared as `version` everywhere it declares one.
fn declared_as(name: &str, version: i64) -> (Value, Signer) {
    let (mut bundle, signer) = published(name);
    bundle["v"] = Value::from(version);
    bundle["anchor"]["v"] = Value::from(version);
    for entry in bundle["entries"].as_array_mut().expect("entries") {
        entry["v"] = Value::from(version);
    }
    reseal(&mut bundle, &signer);
    (bundle, signer)
}

fn reasons(report: &BundleReport) -> Vec<(String, Option<i64>, Option<String>)> {
    let mut found: Vec<_> = report
        .failures
        .iter()
        .map(|failure| (failure.reason.clone(), failure.seq, failure.node.clone()))
        .collect();
    found.sort();
    found
}

fn at(reason: &str, seq: i64, node: &str) -> (String, Option<i64>, Option<String>) {
    (reason.to_string(), Some(seq), Some(node.to_string()))
}

fn chain_level(reason: &str) -> (String, Option<i64>, Option<String>) {
    (reason.to_string(), None, None)
}

/// A v1 ledger is a supported ledger. Rejecting it outright was this
/// verifier's behaviour until now, and it would fail every v1 row wholesale.
#[test]
fn a_v1_chain_of_the_valid_bundle_is_accepted() {
    let (bundle, signer) = declared_as("valid_bundle_v2", 1);
    let report = verify_bundle(&bundle, &signer);

    assert!(report.accepted, "failures: {:?}", report.failures);
    assert_eq!(report.execution_binding, ExecutionBinding::NotApplicable);
    // The contract's words, as `attenu-bundle` prints them.
    let rendered = serde_json::to_value(&report).expect("report serializes");
    assert_eq!(rendered["execution_binding"], "not applicable");
}

/// The row safal207 specified and rafaelasor accepted for the next revision:
/// the undefined `policy` value is `invalid_policy` on a v1 chain rather than
/// the v2 record check's `invalid_allow`, and it still buys no containment
/// exemption.
#[test]
fn a_v1_chain_reports_an_undefined_policy_as_invalid_policy_and_keeps_containment() {
    let (bundle, signer) = declared_as("reject_unknown_policy_value", 1);
    let report = verify_bundle(&bundle, &signer);

    assert_eq!(
        reasons(&report),
        vec![
            at("containment", 6, "vectors:n1"),
            at("invalid_policy", 6, "vectors:n1"),
        ]
    );
}

/// "Execution binding is checked on `schema_version=2` chains only; on a v1
/// bundle these cannot occur and the report says `not applicable`."
///
/// This asserts only that no binding reason is reported. Whether a v1 entry
/// may carry `call_id` at all is the unpublished v2-only field list, so the
/// verdict on these ledgers is deliberately left open here.
#[test]
fn a_v1_chain_does_not_run_execution_binding() {
    for name in ["reject_duplicate_call_id", "reject_params_mismatch"] {
        let (bundle, signer) = declared_as(name, 1);
        let report = verify_bundle(&bundle, &signer);

        let binding = [
            "duplicate_call_id",
            "duplicate_outcome",
            "outcome_without_allow",
            "outcome_before_allow",
            "params_mismatch",
        ];
        assert!(
            report
                .failures
                .iter()
                .all(|failure| !binding.contains(&failure.reason.as_str())),
            "{name}: {:?}",
            report.failures
        );
        assert_eq!(report.execution_binding, ExecutionBinding::NotApplicable);
        assert!(report.unaccounted_calls.is_empty(), "{name}");
    }
}

#[test]
fn a_v2_chain_still_runs_execution_binding() {
    let (bundle, signer) = published("valid_bundle_v2");
    let report = verify_bundle(&bundle, &signer);

    assert_eq!(report.execution_binding, ExecutionBinding::Checked);
}

/// The contract's token is `unsupported_version`. This verifier used to report
/// `unsupported_schema_version`, a name of its own that no row had checked.
#[test]
fn an_unsupported_version_is_reported_under_the_contract_token() {
    let (bundle, signer) = declared_as("valid_bundle_v2", 3);
    let report = verify_bundle(&bundle, &signer);

    assert!(reasons(&report).contains(&chain_level("unsupported_version")));
    assert!(report
        .failures
        .iter()
        .all(|failure| failure.reason != "unsupported_schema_version"));
}

#[test]
fn an_anchor_declaring_another_version_is_reported_at_chain_level() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["anchor"]["v"] = Value::from(1);
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(
        reasons(&report),
        vec![chain_level("anchor_version_mismatch")]
    );
}

/// The root is an entry, so when it is the first to disagree it is also "the
/// first such entry" for `mixed_entry_versions`. The README states no
/// exemption for it; if one is meant, it is a question for the thread, not
/// something to write in here unasked.
#[test]
fn a_root_declaring_another_version_is_reported_on_the_root() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][0]["v"] = Value::from(1);
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(
        reasons(&report),
        vec![
            at("mixed_entry_versions", 0, "vectors:n0"),
            at("root_version_mismatch", 0, "vectors:n0"),
        ]
    );
}

/// Reported once, at the first entry that disagrees: the rest of a mixed
/// ledger is the same finding, not new ones.
#[test]
fn entries_declaring_another_version_are_reported_at_the_first_one() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][3]["v"] = Value::from(1);
    bundle["entries"][5]["v"] = Value::from(1);
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(
        reasons(&report),
        vec![at("mixed_entry_versions", 3, "vectors:n0")]
    );
}
