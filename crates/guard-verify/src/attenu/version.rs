//! Schema version: which versions this verifier reads, and whether a ledger
//! declares one version everywhere it declares one.
//!
//! The token names are the corpus README's (`unsupported_version`,
//! `anchor_version_mismatch`, `root_version_mismatch`,
//! `mixed_entry_versions`). No row in `bundle_vectors_v1.4` exercises them:
//! every published bundle is a consistent `schema_version=2` chain.

use super::{entry_str, Failure};
use serde_json::Value;

/// The two versions the format defines.
pub const V1: i64 = 1;
pub const V2: i64 = 2;

/// Check the declared versions and return the bundle's, if it declares one.
///
/// A mixed ledger is reported once, at the first entry that disagrees: the
/// entries after it are the same finding rather than new ones. That entry may
/// be the root, which then carries both reasons — the README positions
/// `mixed_entry_versions` on "the first such entry" and exempts no entry from
/// being one. An entry that declares no `v` at all declares nothing to
/// disagree with.
pub fn check_versions(
    bundle: &Value,
    entries: &[Value],
    failures: &mut Vec<Failure>,
) -> Option<i64> {
    let declared = bundle.get("v").and_then(Value::as_i64);
    if !matches!(declared, Some(V1 | V2)) {
        failures.push(Failure::chain_level("unsupported_version"));
    }
    let version = declared?;

    let anchor_version = bundle
        .get("anchor")
        .and_then(|anchor| anchor.get("v"))
        .and_then(Value::as_i64);
    if anchor_version.is_some_and(|anchor_version| anchor_version != version) {
        failures.push(Failure::chain_level("anchor_version_mismatch"));
    }

    let mut mixed_reported = false;
    for entry in entries {
        let Some(entry_version) = entry.get("v").and_then(Value::as_i64) else {
            continue;
        };
        if entry_version == version {
            continue;
        }
        if entry_str(entry, "event").as_deref() == Some("root") {
            failures.push(Failure::at(entry, "root_version_mismatch"));
        }
        if !mixed_reported {
            failures.push(Failure::at(entry, "mixed_entry_versions"));
            mixed_reported = true;
        }
    }

    Some(version)
}
