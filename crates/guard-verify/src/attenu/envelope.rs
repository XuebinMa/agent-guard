//! Observer envelopes: was a delegation event signed from outside the process
//! that recorded it?
//!
//! Written against the format description in `attenu-io/attenu-guard`
//! `tests/vectors/README.md` and the per-case prose in
//! `envelope_vectors_v1.json`, like the rest of this module, and without
//! reading either reference implementation.
//!
//! The ledger already proves an entry has not moved. An envelope answers the
//! one thing the ledger cannot: whether anything outside the writing process
//! ever saw the event. So the signature covers the entry's *identity* — its
//! `entry_hash`, which commits to the entry and, through `prev_hash`, to its
//! position in the chain — and never the contents, which the entry's own hash
//! already covers.
//!
//! Two properties shape the code more than anything else:
//!
//! - **An envelope is never required, and a present one must verify.** Absence
//!   is the status quo, so a bundle without them is the bundle it always was.
//!   A broken one is a bundle failure, not a downgrade.
//! - **A bundle is attacker-supplied, so nothing here raises.** Every member
//!   is an untrusted JSON value of any type, and each malformed shape is a
//!   named reason rather than a panic. `witness_keys` is the exception: those
//!   come from the deployment, so a malformed row there is the caller's bug
//!   and is returned as an error naming its `kid`.

use std::collections::{BTreeSet, HashMap};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{chain, Failure};
use crate::jcs;

const ENVELOPE_VERSION: i64 = 1;
const ENVELOPE_TYP: &str = "delegation-event-observation";
const WITNESS_ALG: &str = "EdDSA";

const TOP_MEMBERS: [&str; 6] = ["v", "typ", "subject", "observed", "witness", "sig"];
const OBSERVED_MEMBERS: [&str; 3] = ["result", "at", "method"];
const WITNESS_MEMBERS: [&str; 2] = ["kid", "alg"];
const SPAWN_SUBJECT: [&str; 5] = ["chain_id", "node", "seq", "entry_hash", "event"];
const ALLOW_SUBJECT: [&str; 6] = ["chain_id", "node", "seq", "entry_hash", "event", "call_id"];

/// An Ed25519 key the deployment trusts to witness delegation events.
#[derive(Debug, Clone, Deserialize)]
pub struct WitnessKey {
    pub kid: String,
    pub alg: String,
    pub public_key_hex: String,
}

/// A `witness_keys` row that could not be used. Not a bundle finding: these
/// keys are deployment configuration, so this is the caller's to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessKeyError {
    pub kid: String,
    pub detail: String,
}

impl std::fmt::Display for WitnessKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "witness key {}: {}", self.kid, self.detail)
    }
}

/// What can be said about one entry, once the envelopes have been read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum EntryWitness {
    /// An envelope over this entry verified under a trusted key. The result is
    /// what that witness concluded, and says nothing about authority.
    WitnessSigned { result: Option<String> },
    /// No envelope, or one that did not verify. v1 does not separate "no
    /// witness undertook this hop" from "one did and produced nothing".
    ProcessAsserted,
}

impl EntryWitness {
    /// The state alone, which is what the corpus asserts.
    pub fn state(&self) -> &'static str {
        match self {
            EntryWitness::WitnessSigned { .. } => "witness-signed",
            EntryWitness::ProcessAsserted => "process-asserted",
        }
    }
}

/// The envelope layer's view of one bundle.
#[derive(Debug, Clone, Serialize)]
pub struct EnvelopeReport {
    /// One per ledger entry, in entry order.
    pub states: Vec<EntryWitness>,
    /// The JCS preimage each envelope's signature was checked against, in
    /// array order. Exposed because a verifier that accepts while
    /// canonicalizing different bytes is exactly the one that agrees on a
    /// corpus and disagrees in production.
    pub canonical: Vec<Option<Vec<u8>>>,
}

/// The trusted keys, parsed once.
pub struct TrustSet {
    keys: HashMap<String, VerifyingKey>,
}

impl TrustSet {
    pub fn build(keys: &[WitnessKey]) -> Result<TrustSet, WitnessKeyError> {
        let mut parsed = HashMap::new();
        for key in keys {
            if !key.alg.eq_ignore_ascii_case(WITNESS_ALG) {
                return Err(WitnessKeyError {
                    kid: key.kid.clone(),
                    detail: format!("alg {} is not {WITNESS_ALG}", key.alg),
                });
            }
            let bytes = hex::decode(&key.public_key_hex).map_err(|error| WitnessKeyError {
                kid: key.kid.clone(),
                detail: format!("public_key_hex is not hex: {error}"),
            })?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| WitnessKeyError {
                kid: key.kid.clone(),
                detail: "public key is not 32 bytes".to_string(),
            })?;
            let verifying = VerifyingKey::from_bytes(&bytes).map_err(|error| WitnessKeyError {
                kid: key.kid.clone(),
                detail: format!("not a valid Ed25519 public key: {error}"),
            })?;
            parsed.insert(key.kid.clone(), verifying);
        }
        Ok(TrustSet { keys: parsed })
    }
}

/// Read the envelopes beside a ledger and report a state for every entry.
///
/// `received` supplies the bytes an envelope arrived as, by array index, for
/// deployments that kept them. Canonicality is the one check that cannot be
/// made from a parsed object, because escaping and member order do not survive
/// a parse — so where bytes are absent that check does not run, and the entry
/// is not thereby more trusted than one where it did.
pub(super) fn check_envelopes(
    bundle: &Value,
    entries: &[Value],
    trust: &TrustSet,
    received: &HashMap<usize, Vec<u8>>,
    failures: &mut Vec<Failure>,
) -> EnvelopeReport {
    let mut states = vec![EntryWitness::ProcessAsserted; entries.len()];

    let Some(envelopes) = bundle.get("envelopes").and_then(Value::as_array) else {
        // No array at all: every bundle written before this contract existed.
        return EnvelopeReport {
            states,
            canonical: Vec::new(),
        };
    };

    let mut canonical = vec![None; envelopes.len()];
    let mut claimed: HashMap<i64, usize> = HashMap::new();

    for (index, envelope) in envelopes.iter().enumerate() {
        let subject_seq = envelope
            .get("subject")
            .and_then(|subject| subject.get("seq"))
            .and_then(Value::as_i64);
        let found = subject_seq.and_then(|seq| entry_index_for_seq(entries, seq));

        // The entry is claimed the moment `subject.seq` finds it, before the
        // envelope is judged on anything else. Otherwise a second envelope
        // over the same entry could escape the one-envelope rule by also being
        // malformed, and whichever envelope was read last would decide the
        // entry's state — so the same bundle in the other array order would
        // score differently.
        if let (Some(seq), Some(entry_index)) = (subject_seq, found) {
            if claimed.contains_key(&seq) {
                failures.push(Failure::at(
                    &entries[entry_index],
                    "envelope_duplicate_subject",
                ));
                states[entry_index] = EntryWitness::ProcessAsserted;
                continue;
            }
            claimed.insert(seq, index);
        }

        let position = found.map(|entry_index| &entries[entry_index]);
        let before = failures.len();

        canonical[index] = judge(
            envelope,
            entries,
            found,
            position,
            trust,
            received.get(&index).map(Vec::as_slice),
            failures,
        );

        if failures.len() == before {
            if let Some(entry_index) = found {
                states[entry_index] = EntryWitness::WitnessSigned {
                    result: envelope
                        .get("observed")
                        .and_then(|observed| observed.get("result"))
                        .and_then(Value::as_str)
                        .map(str::to_string),
                };
            }
        }
    }

    EnvelopeReport { states, canonical }
}

/// Every check for one envelope, reporting each thing wrong with it.
///
/// Returns the canonical preimage when one could be produced.
fn judge(
    envelope: &Value,
    entries: &[Value],
    found: Option<usize>,
    position: Option<&Value>,
    trust: &TrustSet,
    received: Option<&[u8]>,
    failures: &mut Vec<Failure>,
) -> Option<Vec<u8>> {
    let report = |reason: &str, failures: &mut Vec<Failure>| match position {
        Some(entry) => failures.push(Failure::at(entry, reason)),
        None => failures.push(Failure {
            reason: reason.to_string(),
            seq: envelope
                .get("subject")
                .and_then(|subject| subject.get("seq"))
                .and_then(Value::as_i64),
            node: None,
        }),
    };

    // A different version or type is a different contract, so nothing below is
    // meaningful to check against this one.
    let known_version = envelope.get("v").and_then(Value::as_i64) == Some(ENVELOPE_VERSION)
        && envelope.get("typ").and_then(Value::as_str) == Some(ENVELOPE_TYP);
    if !known_version {
        report("envelope_unknown_version", failures);
        return None;
    }

    if has_unknown_member(envelope, &TOP_MEMBERS)
        || envelope
            .get("observed")
            .is_some_and(|observed| has_unknown_member(observed, &OBSERVED_MEMBERS))
        || envelope
            .get("witness")
            .is_some_and(|witness| has_unknown_member(witness, &WITNESS_MEMBERS))
        || subject_has_unknown_member(envelope)
    {
        report("envelope_unknown_member", failures);
    }

    if !subject_matches(envelope, entries, found) {
        report("envelope_subject_mismatch", failures);
    }

    let mut body = envelope.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("sig");
    }
    let preimage = match jcs::canonicalize(&body) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            // A value JCS cannot represent at all. There is no preimage to
            // check a signature against, so this is where the envelope stops.
            report("envelope_non_canonical", failures);
            None
        }
    };

    if let Some(raw) = received {
        // Bytes that are not the canonical form of what they parse to were
        // written by something that did not canonicalize, whatever else is
        // true of them.
        if jcs::canonicalize(envelope).ok().as_deref() != Some(raw) {
            report("envelope_non_canonical", failures);
        }
    }

    let kid = envelope
        .get("witness")
        .and_then(|witness| witness.get("kid"))
        .and_then(Value::as_str);
    let alg = envelope
        .get("witness")
        .and_then(|witness| witness.get("alg"))
        .and_then(Value::as_str);

    // The alg is contract, not negotiation. Comparing it only against the
    // trust-set row would accept "none" the moment both sides said so;
    // ignoring it would hand an HS256 envelope to an Ed25519 verifier and
    // report a signature failure on an envelope whose signature was never the
    // problem.
    let key = match (kid, alg) {
        (Some(kid), Some(alg)) if alg == WITNESS_ALG => trust.keys.get(kid),
        _ => None,
    };
    let Some(key) = key else {
        report("envelope_unknown_witness", failures);
        return preimage;
    };

    match (envelope.get("sig").and_then(Value::as_str), &preimage) {
        (Some(sig), Some(preimage)) => {
            let verified = hex::decode(sig)
                .ok()
                .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
                .map(|bytes| Signature::from_bytes(&bytes))
                .is_some_and(|signature| key.verify_strict(preimage, &signature).is_ok());
            if !verified {
                report("envelope_bad_signature", failures);
            }
        }
        _ => report("envelope_bad_signature", failures),
    }

    preimage
}

fn has_unknown_member(value: &Value, allowed: &[&str]) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    map.keys().any(|key| !allowed.contains(&key.as_str()))
}

/// A member added to the subject is unknown; a member its event requires and
/// does not carry is a subject mismatch. The direction matters, so the two are
/// separated here rather than compared as one set.
fn subject_has_unknown_member(envelope: &Value) -> bool {
    let Some(subject) = envelope.get("subject").and_then(Value::as_object) else {
        return false;
    };
    let allowed: &[&str] = match subject.get("event").and_then(Value::as_str) {
        Some("allow") => &ALLOW_SUBJECT,
        Some("spawn") => &SPAWN_SUBJECT,
        // v1 defines no subject for any other event, which `subject_matches`
        // reports; against no defined set nothing here can be called extra.
        _ => return false,
    };
    subject.keys().any(|key| !allowed.contains(&key.as_str()))
}

/// The subject names one entry, and the entry it names has to be the one it
/// describes.
///
/// `entry_hash` is the binding member, so it is recomputed from the bundle
/// rather than read from beside it. The rest are locators, checked against the
/// entry `seq` found — not against the entry the locators themselves would
/// suggest, which is how a subject pointing at a real but wrong entry is
/// caught.
fn subject_matches(envelope: &Value, entries: &[Value], found: Option<usize>) -> bool {
    let Some(subject) = envelope.get("subject").and_then(Value::as_object) else {
        return false;
    };
    let Some(event) = subject.get("event").and_then(Value::as_str) else {
        return false;
    };
    let required: &[&str] = match event {
        "spawn" => &SPAWN_SUBJECT,
        "allow" => &ALLOW_SUBJECT,
        _ => return false,
    };
    if required.iter().any(|member| !subject.contains_key(*member)) {
        return false;
    }
    if subject.get("seq").and_then(Value::as_i64).is_none() {
        return false;
    }

    let Some(entry_index) = found else {
        return false;
    };
    let entry = &entries[entry_index];

    let Ok(recomputed) = chain::entry_hash_of(entries, entry_index) else {
        return false;
    };
    if subject.get("entry_hash").and_then(Value::as_str) != Some(recomputed.as_str()) {
        return false;
    }

    let locators: BTreeSet<&str> = required
        .iter()
        .copied()
        .filter(|member| *member != "seq" && *member != "entry_hash")
        .collect();
    locators
        .iter()
        .all(|member| subject.get(*member) == entry.get(*member))
}

fn entry_index_for_seq(entries: &[Value], seq: i64) -> Option<usize> {
    entries
        .iter()
        .position(|entry| entry.get("seq").and_then(Value::as_i64) == Some(seq))
}
