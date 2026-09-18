//! Offline verifier for attenu-guard evidence bundles (schema v1 and v2).
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
//! 3. on a `schema_version=2` chain, every `call_id` is issued once and every
//!    outcome binds to exactly one authorization, ordered before it, on the
//!    same node, with the arguments that were authorized (on a v1 chain the
//!    binding is "not applicable");
//! 4. every delegation is a subset of its parent and every allowed scope was
//!    inside the acting node's authority;
//! 5. the bundle, its anchor and its entries declare one version;
//! 6. the ledger has exactly one root and names one chain throughout.
//!
//! The report also carries the counters a case may pin in `expect_report`,
//! under the corpus's own names: `actions_checked` and `ungated`.
//!
//! Not implemented, and not claimed:
//!
//! - `v2_field_on_v1`. The README names the reason but not which entry fields
//!   are v2-only, and guessing the list would fail the canonical v1 rows it
//!   cannot see.
//! - The v2 record schema behind `invalid_root`, `invalid_kill`,
//!   `invalid_deny` and `invalid_outcome`, and `invalid_allow` beyond the
//!   `policy` value.
//! - `expected_head_mismatch` and `expected_anchor_mismatch`, which need an
//!   independently retained head or anchor that this verifier is not given.

mod authority;
mod binding;
mod chain;
pub mod corpus;
mod envelope;
mod structure;
mod version;

pub use envelope::{EntryWitness, EnvelopeReport, TrustSet, WitnessKey};

use std::collections::HashMap;

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

/// Whether the execution-binding pass ran on this ledger.
///
/// The format checks binding on `schema_version=2` chains only; on a v1 chain
/// the report says "not applicable" rather than implying the pairs were found
/// sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExecutionBinding {
    #[serde(rename = "checked")]
    Checked,
    #[serde(rename = "not applicable")]
    NotApplicable,
    /// Verification never started, e.g. the trust set could not be built.
    /// Distinct from `NotApplicable`, which is a statement about the format.
    #[serde(rename = "not run")]
    NotRun,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleReport {
    pub accepted: bool,
    pub failures: Vec<Failure>,
    pub execution_binding: ExecutionBinding,
    /// Allows measured against the acting node's authority. This and
    /// `ungated` are the corpus's `expect_report` counters, under its names.
    pub actions_checked: usize,
    /// Allows let through without an authorization check, marked
    /// `"policy": "unlisted"`: recorded, and deliberately not measured.
    pub ungated: usize,
    /// Authorized calls with no terminal observation. Not a failure: it
    /// bounds what the ledger proves rather than showing a broken rule.
    pub unaccounted_calls: Vec<String>,
    /// What the observer envelopes beside this ledger establish. `None` when
    /// no trust set was supplied, which is not the same as an empty one: with
    /// no keys, nothing could have been witness-signed.
    pub envelopes: Option<EnvelopeReport>,
}

/// Verify one evidence bundle against its signer.
pub fn verify_bundle(bundle: &Value, signer: &Signer) -> BundleReport {
    verify(bundle, Some(signer), None, &HashMap::new())
}

/// Verify a bundle and the observer envelopes travelling beside it.
///
/// `signer` is optional because a bundle may carry no anchor at all, and an
/// absent anchor is not an envelope failure: running the anchor check anyway
/// would report a chain-level failure caused by nothing the ledger did.
///
/// `received` supplies the bytes an envelope arrived as, by array index, for
/// deployments that kept them.
pub fn verify_bundle_with_envelopes(
    bundle: &Value,
    signer: Option<&Signer>,
    trust: &TrustSet,
    received: &HashMap<usize, Vec<u8>>,
) -> BundleReport {
    verify(bundle, signer, Some(trust), received)
}

fn verify(
    bundle: &Value,
    signer: Option<&Signer>,
    trust: Option<&TrustSet>,
    received: &HashMap<usize, Vec<u8>>,
) -> BundleReport {
    let mut failures = Vec::new();

    let entries = bundle
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let schema_version = version::check_versions(bundle, &entries, &mut failures);
    structure::check_root_count(&entries, &mut failures);
    structure::check_chain_ids(bundle, &entries, &mut failures);
    if let Some(c14n) = bundle.get("c14n").and_then(Value::as_str) {
        if c14n != "JCS" {
            // Outside the contract: the README has no token for this, so the
            // name is this verifier's own until a revision adds a row for it.
            failures.push(Failure::chain_level("unsupported_canonicalization"));
        }
    }

    chain::check_entries(&entries, &mut failures);
    if let Some(signer) = signer {
        chain::check_anchor(bundle.get("anchor"), &entries, signer, &mut failures);
    }

    // "Execution binding is checked on `schema_version=2` chains only; on a
    // v1 bundle these cannot occur and the report says `not applicable`."
    // A version this verifier does not read is checked as v2: it is already
    // rejected, and reporting what can still be established beats reporting
    // less.
    let (execution_binding, unaccounted_calls) = if schema_version == Some(version::V1) {
        (ExecutionBinding::NotApplicable, Vec::new())
    } else {
        binding::check_call_id_uniqueness(&entries, &mut failures);
        let unaccounted = binding::check_execution_binding(&entries, &mut failures);
        (ExecutionBinding::Checked, unaccounted)
    };

    authority::check_policy_field(&entries, schema_version, &mut failures);
    let measured = authority::check_authority(&entries, &mut failures);

    let envelopes = trust
        .map(|trust| envelope::check_envelopes(bundle, &entries, trust, received, &mut failures));

    BundleReport {
        accepted: failures.is_empty(),
        failures,
        execution_binding,
        actions_checked: measured.actions_checked,
        ungated: measured.ungated,
        unaccounted_calls,
        envelopes,
    }
}

fn entry_str(entry: &Value, key: &str) -> Option<String> {
    entry.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod version_tests;
