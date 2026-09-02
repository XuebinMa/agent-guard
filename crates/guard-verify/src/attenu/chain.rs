//! Ledger integrity: the hash chain and the signed anchor over its head.

use super::{Failure, Signer};
use crate::jcs;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Recompute every entry hash from the entry body and the previous hash.
///
/// The preimage is the ASCII previous-hash string followed by the canonical
/// bytes of the entry with its own `hash` field removed.
pub fn check_entries(entries: &[Value], failures: &mut Vec<Failure>) {
    for (index, entry) in entries.iter().enumerate() {
        let expected_prev = if index == 0 {
            GENESIS_PREV.to_string()
        } else {
            super::entry_str(&entries[index - 1], "hash").unwrap_or_default()
        };

        let stored_prev = super::entry_str(entry, "prev_hash").unwrap_or_default();
        let stored_hash = super::entry_str(entry, "hash").unwrap_or_default();

        if stored_prev != expected_prev {
            failures.push(Failure::at(entry, "integrity"));
            continue;
        }

        match recompute_entry_hash(entry, &stored_prev) {
            Ok(recomputed) if recomputed == stored_hash => {}
            Ok(_) => failures.push(Failure::at(entry, "integrity")),
            Err(_) => failures.push(Failure::at(entry, "integrity")),
        }
    }
}

fn recompute_entry_hash(entry: &Value, prev_hash: &str) -> Result<String, jcs::JcsError> {
    let mut body = entry.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("hash");
    }
    let canonical = jcs::canonicalize(&body)?;

    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

/// Recompute the chain head from genesis, using each entry's own body rather
/// than the hash stored next to it.
///
/// The anchor exists precisely because stored hashes can be rewritten, so the
/// head it is compared against must be derived, never read.
fn recompute_head(entries: &[Value]) -> Option<String> {
    let mut prev = GENESIS_PREV.to_string();
    for entry in entries {
        prev = recompute_entry_hash(entry, &prev).ok()?;
    }
    Some(prev)
}

/// Verify the anchor signature and that it commits to the head this ledger
/// actually reproduces.
///
/// The anchor's own `verified` field is the producer's claim about itself and
/// is deliberately ignored.
pub fn check_anchor(
    anchor: Option<&Value>,
    entries: &[Value],
    signer: &Signer,
    failures: &mut Vec<Failure>,
) {
    let Some(anchor) = anchor else {
        failures.push(Failure::chain_level("integrity(anchor)"));
        return;
    };

    let mut body = anchor.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("kid");
        map.remove("sig");
        map.remove("verified");
    }

    let Ok(canonical) = jcs::canonicalize(&body) else {
        failures.push(Failure::chain_level("integrity(anchor)"));
        return;
    };

    let Ok(secret) = hex::decode(&signer.secret_hex) else {
        failures.push(Failure::chain_level("integrity(anchor)"));
        return;
    };

    if !signer.alg.eq_ignore_ascii_case("HS256") {
        failures.push(Failure::chain_level("unsupported_anchor_alg"));
        return;
    }

    let mut mac = match Hmac::<Sha256>::new_from_slice(&secret) {
        Ok(mac) => mac,
        Err(_) => {
            failures.push(Failure::chain_level("integrity(anchor)"));
            return;
        }
    };
    mac.update(&canonical);
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    let stored_sig = anchor
        .get("sig")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if expected_sig != stored_sig {
        failures.push(Failure::chain_level("integrity(anchor)"));
        return;
    }

    let Some(head) = recompute_head(entries) else {
        failures.push(Failure::chain_level("integrity(anchor)"));
        return;
    };
    let anchored_head = anchor
        .get("head")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if head != anchored_head {
        failures.push(Failure::chain_level("integrity(anchor)"));
    }
}
