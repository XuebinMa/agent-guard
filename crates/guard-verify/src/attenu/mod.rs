//! Offline verifier for attenu-guard evidence bundles (schema v2).
//!
//! This is a from-scratch, third-party implementation written against the
//! published format description in `attenu-io/attenu-guard`
//! `tests/vectors/README.md` and the per-case descriptions in
//! `bundle_vectors_v1.json`. It deliberately does not read, port, or invoke
//! either reference implementation, so agreement between them is evidence
//! about the format rather than about shared code.
//!
//! What a bundle has to satisfy:
//!
//! 1. every entry hash reproduces from the previous hash and the entry body;
//! 2. the anchor signature verifies and commits to the head this ledger
//!    actually reproduces;
//! 3. every `call_id` is issued once;
//! 4. every outcome binds to exactly one authorization, ordered before it, on
//!    the same node, with the arguments that were authorized;
//! 5. every delegation is a subset of its parent and every allowed scope was
//!    inside the acting node's authority.

mod authority;
mod binding;
mod chain;
pub mod corpus;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One rule violation, with the position the rule was broken at.
///
/// `seq` and `node` are `None` for a chain-level failure, where the whole
/// ledger is wrong and there is no single entry to point at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub reason: String,
    pub seq: Option<i64>,
    pub node: Option<String>,
}

impl Failure {
    fn at(entry: &Value, reason: &str) -> Self {
        Failure {
            reason: reason.to_string(),
            seq: entry.get("seq").and_then(Value::as_i64),
            node: entry_str(entry, "node"),
        }
    }

    fn chain_level(reason: &str) -> Self {
        Failure {
            reason: reason.to_string(),
            seq: None,
            node: None,
        }
    }
}

/// The anchor signer. Only HS256 is accepted here, which is what the
/// interoperability corpus publishes; a production ledger signs with Ed25519.
#[derive(Debug, Clone, Deserialize)]
pub struct Signer {
    pub alg: String,
    pub secret_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleReport {
    pub accepted: bool,
    pub failures: Vec<Failure>,
    /// Authorized calls with no terminal observation. Not a failure: it
    /// bounds what the ledger proves rather than showing a broken rule.
    pub unaccounted_calls: Vec<String>,
}

/// Verify one evidence bundle against its signer.
pub fn verify_bundle(bundle: &Value, signer: &Signer) -> BundleReport {
    let mut failures = Vec::new();

    let entries = bundle
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if bundle.get("v").and_then(Value::as_i64) != Some(2) {
        failures.push(Failure::chain_level("unsupported_schema_version"));
    }
    if let Some(c14n) = bundle.get("c14n").and_then(Value::as_str) {
        if c14n != "JCS" {
            failures.push(Failure::chain_level("unsupported_canonicalization"));
        }
    }

    chain::check_entries(&entries, &mut failures);
    chain::check_anchor(bundle.get("anchor"), &entries, signer, &mut failures);
    binding::check_call_id_uniqueness(&entries, &mut failures);
    let unaccounted_calls = binding::check_execution_binding(&entries, &mut failures);
    authority::check_authority(&entries, &mut failures);

    BundleReport {
        accepted: failures.is_empty(),
        failures,
        unaccounted_calls,
    }
}

fn entry_str(entry: &Value, key: &str) -> Option<String> {
    entry.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests;
