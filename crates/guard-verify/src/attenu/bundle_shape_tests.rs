//! Container failures stop verification before interpreting ledger claims.
//! These harmless JSON fixtures exercise both public verifier entry points.

use super::test_support::published;
use super::*;
use serde_json::json;

fn both_reports(bundle: &Value, signer: &Signer) -> [BundleReport; 2] {
    let trust = TrustSet::build(&[]).expect("empty trust set is valid");
    [
        verify_bundle(bundle, signer),
        verify_bundle_with_envelopes(bundle, Some(signer), &trust, &HashMap::new()),
    ]
}

fn assert_container_failure(report: &BundleReport, count: usize) {
    assert!(!report.accepted);
    assert_eq!(report.failures.len(), count, "{:?}", report.failures);
    for failure in &report.failures {
        assert_eq!(failure.reason, "invalid_bundle");
        assert_eq!(failure.seq, None);
        assert_eq!(failure.node, None);
    }
    assert_eq!(report.execution_binding, ExecutionBinding::NotRun);
    assert_eq!(report.actions_checked, 0);
    assert_eq!(report.ungated, 0);
    assert!(report.unaccounted_calls.is_empty());
    assert!(report.envelopes.is_none(), "the envelope pass did not run");
}

#[test]
fn non_object_bundles_are_one_chain_level_container_failure() {
    let (_, signer) = published("valid_bundle_v2");
    for bundle in [
        json!(null),
        json!(false),
        json!(7),
        json!("bundle"),
        json!([]),
    ] {
        for report in both_reports(&bundle, &signer) {
            assert_container_failure(&report, 1);
        }
    }
}

#[test]
fn wrong_container_types_stop_every_semantic_pass_on_both_apis() {
    for member in ["entries", "envelopes", "anchor"] {
        for value in [
            json!(false),
            json!(7),
            json!(1.5),
            json!("wrong container"),
            if member == "anchor" {
                json!([])
            } else {
                json!({})
            },
        ] {
            let (mut bundle, signer) = published("valid_bundle_v2_ungated_allow");
            // Even an unknown root cannot be interpreted after a container
            // failure. The valid ledger also has nonzero measured counters.
            bundle["entries"][0]["event"] = json!("future-root");
            bundle[member] = value;
            for report in both_reports(&bundle, &signer) {
                assert_container_failure(&report, 1);
            }
        }
    }
}

#[test]
fn wrong_envelope_container_cannot_be_accepted_as_absence() {
    for value in [
        json!(false),
        json!(7),
        json!(1.5),
        json!("envelopes"),
        json!({}),
    ] {
        let (mut bundle, signer) = published("valid_bundle_v2");
        // No ledger claim is altered: this was accepted when a wrong-type
        // envelopes member was silently treated as if it were absent.
        assert!(verify_bundle(&bundle, &signer).accepted);
        bundle["envelopes"] = value;
        for report in both_reports(&bundle, &signer) {
            assert_container_failure(&report, 1);
        }
    }
}

#[test]
fn every_wrong_container_member_has_exactly_one_failure() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"] = json!({});
    bundle["envelopes"] = json!(true);
    bundle["anchor"] = json!([]);
    for report in both_reports(&bundle, &signer) {
        assert_container_failure(&report, 3);
    }
}

#[test]
fn null_entries_keep_the_same_semantics_as_absent_entries() {
    let (mut absent, signer) = published("valid_bundle_v2");
    absent.as_object_mut().unwrap().remove("entries");
    let mut null = absent.clone();
    null["entries"] = Value::Null;
    for (absent_report, null_report) in both_reports(&absent, &signer)
        .iter()
        .zip(both_reports(&null, &signer))
    {
        assert_eq!(
            serde_json::to_value(absent_report).unwrap(),
            serde_json::to_value(null_report).unwrap()
        );
        assert!(absent_report
            .failures
            .iter()
            .all(|f| f.reason != "invalid_bundle"));
    }
}

#[test]
fn null_anchor_means_absence_with_or_without_an_anchor_signer() {
    let (mut absent, signer) = published("valid_bundle_v2");
    absent.as_object_mut().unwrap().remove("anchor");
    let mut null = absent.clone();
    null["anchor"] = Value::Null;
    for (absent_report, null_report) in both_reports(&absent, &signer)
        .iter()
        .zip(both_reports(&null, &signer))
    {
        assert_eq!(
            serde_json::to_value(absent_report).unwrap(),
            serde_json::to_value(null_report).unwrap()
        );
        assert_eq!(absent_report.failures.len(), 1);
        assert_eq!(absent_report.failures[0].reason, "integrity(anchor)");
    }
    let trust = TrustSet::build(&[]).unwrap();
    for bundle in [&absent, &null] {
        let report = verify_bundle_with_envelopes(bundle, None, &trust, &HashMap::new());
        assert!(report.accepted, "{:?}", report.failures);
    }
}

#[test]
fn null_and_absent_envelopes_keep_the_empty_array_semantics() {
    let (mut absent, signer) = published("valid_bundle_v2_ungated_allow");
    absent.as_object_mut().unwrap().remove("envelopes");
    let mut null = absent.clone();
    null["envelopes"] = Value::Null;
    let mut empty = absent.clone();
    empty["envelopes"] = json!([]);
    let trust = TrustSet::build(&[]).unwrap();
    let expected = verify_bundle_with_envelopes(&empty, Some(&signer), &trust, &HashMap::new());
    assert!(expected.accepted, "{:?}", expected.failures);
    assert_eq!(expected.actions_checked, 2);
    assert_eq!(expected.ungated, 1);
    for bundle in [&absent, &null] {
        let report = verify_bundle_with_envelopes(bundle, Some(&signer), &trust, &HashMap::new());
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
    }
}

#[test]
fn non_object_ledger_entries_have_an_unambiguous_array_index() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"] = json!([null, false, 7, "entry", []]);
    for report in both_reports(&bundle, &signer) {
        let malformed: Vec<_> = report
            .failures
            .iter()
            .filter(|failure| failure.reason == "invalid_ledger_entry")
            .map(|failure| serde_json::to_value(failure).unwrap())
            .collect();
        let expected: Vec<_> = (0..5)
            .map(|index| {
                json!({
                    "reason":"invalid_ledger_entry", "seq":null, "node":null, "entry_index":index
                })
            })
            .collect();
        assert_eq!(malformed, expected);
    }
}

#[test]
fn ordinary_failure_json_keeps_its_existing_shape() {
    let failure = Failure::chain_level("invalid_bundle");
    let old_shape = json!({"reason":"invalid_bundle", "seq":null, "node":null});
    assert_eq!(serde_json::to_value(&failure).unwrap(), old_shape);
    assert_eq!(
        serde_json::from_value::<Failure>(old_shape).unwrap(),
        failure
    );
}
