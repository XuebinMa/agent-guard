//! Negative schema vectors derived from the published accepting bundle.
//!
//! Each mutation is re-hashed and re-anchored. A failure therefore proves the
//! verifier rejected a signed shape it does not understand, not merely that
//! the original integrity seal no longer matched.

use super::test_support::{at, chain_level, published, reasons, reseal};
use super::*;
use serde_json::json;

const V2_ONLY_FIELDS: [&str; 12] = [
    "adapter",
    "authorized_params_hash",
    "body_state",
    "call_id",
    "capture",
    "duration_ms",
    "error_code",
    "invoked_params_hash",
    "params_hash_reason",
    "params_salt",
    "pending_at_kill",
    "receipt",
];

fn as_v1(bundle: &mut Value) {
    bundle["v"] = Value::from(1);
    bundle["anchor"]["v"] = Value::from(1);
    for entry in bundle["entries"].as_array_mut().expect("entries") {
        entry["v"] = Value::from(1);
        let object = entry.as_object_mut().expect("entry object");
        for field in V2_ONLY_FIELDS {
            object.remove(field);
        }
    }
}

fn report_after(mut bundle: Value, signer: &Signer) -> BundleReport {
    reseal(&mut bundle, signer);
    verify_bundle(&bundle, signer)
}

#[test]
fn a_signed_unknown_ledger_field_is_not_silently_projected_away() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][1]["critical"] = Value::Bool(true);

    let report = report_after(bundle, &signer);
    assert!(reasons(&report).contains(&at("unknown_ledger_fields", 1, "vectors:n1")));
}

#[test]
fn an_unknown_event_is_not_reported_as_a_verified_no_op() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][7]["event"] = Value::from("execute_anything");

    let report = report_after(bundle, &signer);
    assert!(reasons(&report).contains(&at("unknown_ledger_event", 7, "vectors:n1")));
}

#[test]
fn a_v1_entry_carrying_any_v2_field_is_rejected() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    as_v1(&mut bundle);
    bundle["entries"][2]["call_id"] = Value::from("a".repeat(32));

    let report = report_after(bundle, &signer);
    assert!(reasons(&report).contains(&at("v2_field_on_v1", 2, "vectors:n0")));
    assert_eq!(report.execution_binding, ExecutionBinding::NotApplicable);
}

#[test]
fn v2_root_schema_rejects_missing_or_malformed_salt() {
    for bad in [Value::Null, Value::from("ABC"), Value::from("a".repeat(31))] {
        let (mut bundle, signer) = published("valid_bundle_v2");
        bundle["entries"][0]["params_salt"] = bad;
        let report = report_after(bundle, &signer);
        assert!(reasons(&report).contains(&at("invalid_root", 0, "vectors:n0")));
    }
}

#[test]
fn v2_allow_schema_rejects_every_load_bearing_malformed_shape() {
    let mutations: Vec<(&str, Value)> = vec![
        ("call_id", Value::Null),
        ("call_id", Value::from("A".repeat(32))),
        ("capture", Value::Null),
        ("capture", Value::from("post_hook_maybe")),
        ("adapter", json!({"module":"m","version":"1"})),
        ("authorized_params_hash", Value::from("0".repeat(63))),
        ("policy", Value::from("made-up")),
    ];

    for (field, value) in mutations {
        let (mut bundle, signer) = published("valid_bundle_v2");
        bundle["entries"][2][field] = value;
        let report = report_after(bundle, &signer);
        assert!(
            reasons(&report).contains(&at("invalid_allow", 2, "vectors:n0")),
            "mutation {field}: {:?}",
            report.failures
        );
    }

    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][2]["params_hash_reason"] = Value::from("unsupported");
    let report = report_after(bundle, &signer);
    assert!(reasons(&report).contains(&at("invalid_allow", 2, "vectors:n0")));
}

#[test]
fn v2_deny_schema_rejects_missing_ids_and_allow_only_fields() {
    for (field, value) in [
        ("call_id", Value::Null),
        ("policy", Value::from("unlisted")),
        ("capture", Value::from("pre_hook_only")),
    ] {
        let (mut bundle, signer) = published("valid_bundle_v2");
        bundle["entries"][5][field] = value;
        let report = report_after(bundle, &signer);
        assert!(
            reasons(&report).contains(&at("invalid_deny", 5, "vectors:n1")),
            "mutation {field}: {:?}",
            report.failures
        );
    }
}

#[test]
fn v2_outcome_schema_rejects_malformed_terminal_claims() {
    let mutations: Vec<(&str, Value)> = vec![
        ("call_id", Value::Null),
        ("body_state", Value::from("executed")),
        ("error_code", Value::from("Unexpected")),
        ("duration_ms", Value::from(-1)),
        ("invoked_params_hash", Value::from("f".repeat(65))),
        ("receipt", json!({"type":"log","ref":"r","digest":"BAD"})),
    ];

    for (field, value) in mutations {
        let (mut bundle, signer) = published("valid_bundle_v2");
        bundle["entries"][3][field] = value;
        let report = report_after(bundle, &signer);
        assert!(
            reasons(&report).contains(&at("invalid_outcome", 3, "vectors:n0")),
            "mutation {field}: {:?}",
            report.failures
        );
    }
}

#[test]
fn v2_kill_schema_rejects_non_call_ids() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][7]["event"] = Value::from("kill");
    bundle["entries"][7]["pending_at_kill"] = json!(["not-a-call-id"]);

    let report = report_after(bundle, &signer);
    assert!(reasons(&report).contains(&at("invalid_kill", 7, "vectors:n1")));
}

#[test]
fn duplicate_ids_across_allow_and_deny_are_ambiguous() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    bundle["entries"][5]["call_id"] = bundle["entries"][2]["call_id"].clone();

    let report = report_after(bundle, &signer);
    assert!(reasons(&report).contains(&at("duplicate_call_id", 5, "vectors:n1")));
}

#[test]
fn malformed_authority_shapes_fail_closed_instead_of_becoming_empty() {
    let mutations = [
        json!({"scopes":"crm.read","constraints":[],"ttl":3600}),
        json!({"scopes":["CRM.read"],"constraints":[],"ttl":3600}),
        json!({"scopes":["crm.read"],"constraints":[{"key":"max_rows","max":10,"min":2}],"ttl":3600}),
        json!({"scopes":["crm.read"],"constraints":[],"ttl":-1}),
        json!({"scopes":["crm.read"],"constraints":[],"ttl":3600,"deny_scopes":["crm.export"]}),
    ];

    for authority in mutations {
        let (mut bundle, signer) = published("valid_bundle_v2");
        bundle["entries"][0]["authority"] = authority;
        let report = report_after(bundle, &signer);
        assert!(
            reasons(&report).contains(&at("unreadable_authority", 0, "vectors:n0")),
            "{:?}",
            report.failures
        );
    }
}

#[test]
fn missing_bundle_version_and_chain_identity_fail_closed() {
    let (mut without_version, signer) = published("valid_bundle_v2");
    without_version.as_object_mut().expect("bundle").remove("v");
    let report = verify_bundle(&without_version, &signer);
    assert!(reasons(&report).contains(&chain_level("unsupported_version")));

    let (mut without_chain, signer) = published("valid_bundle_v2");
    without_chain
        .as_object_mut()
        .expect("bundle")
        .remove("chain_id");
    let report = verify_bundle(&without_chain, &signer);
    assert!(reasons(&report).contains(&chain_level("chain_id_mismatch")));
}

/// The 39 names of the corpus README's "Entry fields" subsection, transcribed
/// from the README rather than read from `schema.rs`, so an edit to either
/// list shows up here as a disagreement.
const PUBLISHED_FIELDS: [&str; 39] = [
    "adapter",
    "agent",
    "authority",
    "authorized_params_hash",
    "body_state",
    "c14n",
    "call_id",
    "capture",
    "chain_id",
    "context",
    "detail",
    "disposition",
    "duration_ms",
    "error_code",
    "event",
    "granted",
    "hash",
    "invoked_params_hash",
    "mode",
    "node",
    "params_hash_reason",
    "params_salt",
    "parent",
    "pending_at_kill",
    "policy",
    "prev_hash",
    "reason",
    "reasons",
    "receipt",
    "requested",
    "revoked",
    "scope",
    "seq",
    "strikes",
    "target",
    "task",
    "tool",
    "ts",
    "v",
];

const UNLISTED_FIELD: &str = "x_unlisted";

/// Where the verifier must position a failure about `bundle`'s entry `index`.
fn placed_on(bundle: &Value, index: usize, reason: &str) -> test_support::Placed {
    let entry = &bundle["entries"][index];
    at(
        reason,
        entry["seq"].as_i64().expect("seq"),
        entry["node"].as_str().expect("node"),
    )
}

fn entry_count(bundle: &Value) -> usize {
    bundle["entries"].as_array().expect("entries").len()
}

/// The controls every sweep below is measured against: re-sealing changes
/// nothing by itself, on either version, so a failure in a sweep belongs to
/// the one field that sweep added.
#[test]
fn the_unmutated_bundle_is_accepted_resealed_on_both_versions() {
    let (v2, signer) = published("valid_bundle_v2");
    let report = report_after(v2, &signer);
    assert!(report.accepted, "v2 failures: {:?}", report.failures);
    assert!(report.failures.is_empty());

    let (mut v1, signer) = published("valid_bundle_v2");
    as_v1(&mut v1);
    let report = report_after(v1, &signer);
    assert!(report.accepted, "v1 failures: {:?}", report.failures);
    assert!(report.failures.is_empty());
}

/// Every v2-only name, on every entry of a v1 chain, is refused once, on that
/// entry, and for no other reason.
#[test]
fn each_v2_only_field_on_each_v1_entry_is_the_only_failure_and_sits_on_that_entry() {
    let (base, signer) = published("valid_bundle_v2");

    for field in V2_ONLY_FIELDS {
        for index in 0..entry_count(&base) {
            let mut bundle = base.clone();
            as_v1(&mut bundle);
            bundle["entries"][index][field] = Value::from("x");
            let expected = vec![placed_on(&bundle, index, "v2_field_on_v1")];

            let report = report_after(bundle, &signer);
            assert!(!report.accepted, "{field} on entry {index} was accepted");
            assert_eq!(reasons(&report), expected, "{field} on entry {index}");
        }
    }
}

/// A field outside the published list is refused once, on the entry carrying
/// it, on a v2 chain and on a v1 chain alike, and for no other reason.
#[test]
fn an_unlisted_field_on_each_entry_is_the_only_failure_and_sits_on_that_entry() {
    let (base, signer) = published("valid_bundle_v2");

    for declare_v1 in [false, true] {
        for index in 0..entry_count(&base) {
            let mut bundle = base.clone();
            if declare_v1 {
                as_v1(&mut bundle);
            }
            bundle["entries"][index][UNLISTED_FIELD] = Value::from(1);
            let expected = vec![placed_on(&bundle, index, "unknown_ledger_fields")];

            let report = report_after(bundle, &signer);
            assert!(
                !report.accepted,
                "v1={declare_v1} entry {index} was accepted"
            );
            assert_eq!(reasons(&report), expected, "v1={declare_v1} entry {index}");
        }
    }
}

/// The two rules are independent: one entry breaking both reports both, and
/// neither hides the other.
#[test]
fn a_v1_entry_with_an_unlisted_field_and_a_v2_only_field_reports_exactly_both() {
    let (mut bundle, signer) = published("valid_bundle_v2");
    as_v1(&mut bundle);
    bundle["entries"][2][UNLISTED_FIELD] = Value::from(1);
    bundle["entries"][2]["receipt"] = Value::from("x");
    let expected = vec![
        placed_on(&bundle, 2, "unknown_ledger_fields"),
        placed_on(&bundle, 2, "v2_field_on_v1"),
    ];

    let report = report_after(bundle, &signer);
    assert!(!report.accepted);
    assert_eq!(reasons(&report), expected);
}

/// The allow-list is the published one in both directions: no published name
/// is ever reported as unknown. A placeholder value may fail that field's own
/// shape rule, which is a different reason and not this test's subject.
#[test]
fn no_published_field_name_is_reported_as_unknown() {
    let (base, signer) = published("valid_bundle_v2");

    for field in PUBLISHED_FIELDS {
        let mut bundle = base.clone();
        let entry = bundle["entries"][2].as_object_mut().expect("entry object");
        entry
            .entry(field.to_string())
            .or_insert_with(|| Value::from("x"));

        let report = report_after(bundle, &signer);
        assert!(
            reasons(&report)
                .iter()
                .all(|(reason, _, _)| reason != "unknown_ledger_fields"),
            "{field}: {:?}",
            report.failures
        );
    }
}

/// The transcription above is the README's: the twelve v2-only names are
/// among the 39, and the remainder is the 27-name v1 form.
#[test]
fn the_transcribed_field_lists_have_the_published_sizes() {
    assert!(V2_ONLY_FIELDS
        .iter()
        .all(|field| PUBLISHED_FIELDS.contains(field)));
    let v1_form = PUBLISHED_FIELDS
        .iter()
        .filter(|field| !V2_ONLY_FIELDS.contains(field))
        .count();
    assert_eq!(v1_form, 27);
    assert!(!PUBLISHED_FIELDS.contains(&UNLISTED_FIELD));
}
