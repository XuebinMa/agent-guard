//! Shared by the tests that derive a bundle from a published case.
//!
//! A derived bundle is re-sealed, so it fails only for the rule under test and
//! never for integrity. The corpus publishes its HS256 secret for exactly this.

use super::corpus::VectorFile;
use super::{BundleReport, Signer};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CORPUS: &str = include_str!("../../fixtures/attenu/bundle_vectors_v1.json");
const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A reason with its position, in a shape that sorts and compares.
pub type Placed = (String, Option<i64>, Option<String>);

pub fn corpus() -> VectorFile {
    serde_json::from_str(CORPUS).expect("corpus parses")
}

pub fn published(name: &str) -> (Value, Signer) {
    let case = corpus()
        .cases
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("case {name} present"));
    (case.bundle, case.signer)
}

/// Recompute every entry hash and re-sign the anchor over the new head.
pub fn reseal(bundle: &mut Value, signer: &Signer) {
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

pub fn reasons(report: &BundleReport) -> Vec<Placed> {
    let mut found: Vec<_> = report
        .failures
        .iter()
        .map(|failure| (failure.reason.clone(), failure.seq, failure.node.clone()))
        .collect();
    found.sort();
    found
}

pub fn at(reason: &str, seq: i64, node: &str) -> Placed {
    (reason.to_string(), Some(seq), Some(node.to_string()))
}

pub fn chain_level(reason: &str) -> Placed {
    (reason.to_string(), None, None)
}
