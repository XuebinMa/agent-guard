//! The rest of the corpus README's contract: reasons its table names that no
//! published row reaches yet, and the counters one row pins that this
//! verifier's scorer never read.
//!
//! Derived cases change one thing in a published case and re-seal it, so each
//! fails for the rule under test and never for integrity.

use super::corpus::score_corpus;
use super::test_support::{at, chain_level, corpus, published, reasons, reseal};
use super::*;

/// `expect_report` is part of the contract: "named counters from the
/// verifier's own report that a conformant implementation MUST reproduce
/// exactly." The one case that pins them today separates a verifier that
/// reports an un-gated allow from one that silently skips it, which the
/// verdict alone cannot do: both accept.
#[test]
fn the_ungated_case_reproduces_the_counters_it_pins() {
    let (bundle, signer) = published("valid_bundle_v2_ungated_allow");
    let report = verify_bundle(&bundle, &signer);

    assert_eq!(report.actions_checked, 2, "the two authorized calls");
    assert_eq!(report.ungated, 1, "the one allow marked `unlisted`");
}

/// "`ungated` is 0 here: nothing was honestly un-gated." The undefined value
/// is measured against authority like any other allow, so it is counted as
/// checked; that half is this verifier's reading, as no row pins it.
#[test]
fn an_undefined_policy_value_is_measured_rather_than_counted_as_ungated() {
    let (bundle, signer) = published("reject_unknown_policy_value");
    let report = verify_bundle(&bundle, &signer);

    assert_eq!(report.ungated, 0);
    assert_eq!(report.actions_checked, 3);
}

/// The scorer used to deserialize past `expect_report` without reading it,
/// so a case could score conformant on its verdict alone.
#[test]
fn a_counter_the_report_disagrees_with_fails_the_case() {
    let mut file = corpus();
    file.cases
        .retain(|case| case.name == "valid_bundle_v2_ungated_allow");
    file.cases[0].expect_report.insert("ungated".to_string(), 0);

    let score = &score_corpus(&file)[0];
    assert!(!score.conformant);
    assert!(
        score
            .problems
            .iter()
            .any(|problem| problem.contains("ungated")),
        "{:?}",
        score.problems
    );
}

/// A counter this verifier does not report cannot be reproduced, so the case
/// fails rather than passing on the counters it happens to know.
#[test]
fn a_counter_this_verifier_does_not_report_fails_the_case() {
    let mut file = corpus();
    file.cases
        .retain(|case| case.name == "valid_bundle_v2_ungated_allow");
    file.cases[0]
        .expect_report
        .insert("tokens_minted".to_string(), 0);

    let score = &score_corpus(&file)[0];
    assert!(!score.conformant);
}

/// "An allow and its outcome sit on different nodes" is `cross_ref`, on the
/// outcome. This verifier called it `outcome_node_mismatch`, a name of its own.
#[test]
fn an_outcome_on_another_node_is_cross_ref() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][3]["node"] = Value::from("vectors:n1");
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(reasons(&report), vec![at("cross_ref", 3, "vectors:n1")]);
}

/// `containment` covers "an `allow` names a node the bundle never spawned".
/// This verifier reported `unreadable_authority`, which the README positions
/// on a root entry only.
#[test]
fn an_allow_by_a_node_never_spawned_is_containment() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][4]["node"] = Value::from("vectors:n9");
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    let found = reasons(&report);
    assert!(
        found.contains(&at("containment", 4, "vectors:n9")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .all(|(reason, _, _)| reason != "unreadable_authority"),
        "{found:?}"
    );
}

/// A parent the ledger never established holds no authority, so a grant from
/// it is not a subset of its parent's: `monotonicity` on the spawn. The table
/// names no reason for this shape; this is the reading that uses one it does.
#[test]
fn a_spawn_from_a_parent_never_established_is_monotonicity() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][1]["parent"] = Value::from("vectors:n9");
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(reasons(&report), vec![at("monotonicity", 1, "vectors:n1")]);
}

/// "The bundle has zero or more than one root event", at chain level.
#[test]
fn a_second_root_is_missing_root_at_chain_level() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    let entries = bundle["entries"].as_array_mut().expect("entries");
    let mut second = entries[0].clone();
    second["seq"] = Value::from(entries.len() as i64);
    entries.push(second);
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(reasons(&report), vec![chain_level("missing_root")]);
}

#[test]
fn a_ledger_with_no_root_is_missing_root_at_chain_level() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"].as_array_mut().expect("entries").remove(0);
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert!(reasons(&report).contains(&chain_level("missing_root")));
}

/// "An entry, or the anchor, names a different chain than the bundle": the
/// foreign entry where it sits, the anchor at chain level.
#[test]
fn an_entry_naming_another_chain_is_reported_on_that_entry() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][4]["chain_id"] = Value::from("elsewhere");
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(
        reasons(&report),
        vec![at("chain_id_mismatch", 4, "vectors:n1")]
    );
}

#[test]
fn an_anchor_naming_another_chain_is_reported_at_chain_level() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["anchor"]["chain_id"] = Value::from("elsewhere");
    reseal(&mut bundle, &signer);

    let report = verify_bundle(&bundle, &signer);
    assert_eq!(reasons(&report), vec![chain_level("chain_id_mismatch")]);
}
