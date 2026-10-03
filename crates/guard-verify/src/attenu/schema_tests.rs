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
