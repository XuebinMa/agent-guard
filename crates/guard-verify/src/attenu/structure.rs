//! Ledger shape: exactly one root, and one chain throughout.

use super::{entry_str, Failure};
use serde_json::Value;

/// "The bundle has zero or more than one root event", at chain level.
pub fn check_root_count(entries: &[Value], failures: &mut Vec<Failure>) {
    let roots = entries
        .iter()
        .filter(|entry| entry_str(entry, "event").as_deref() == Some("root"))
        .count();
    if roots != 1 {
        failures.push(Failure::chain_level("missing_root"));
    }
}

/// An entry, or the anchor, naming a chain other than the bundle's: each
/// foreign entry where it sits, the anchor at chain level.
///
pub fn check_chain_ids(bundle: &Value, entries: &[Value], failures: &mut Vec<Failure>) {
    let Some(chain_id) = bundle
        .get("chain_id")
        .and_then(Value::as_str)
        .filter(|chain_id| !chain_id.is_empty())
    else {
        failures.push(Failure::chain_level("chain_id_mismatch"));
        return;
    };
    let names_another = |value: Option<&Value>| {
        value.is_some_and(|value| value.get("chain_id").and_then(Value::as_str) != Some(chain_id))
    };

    for entry in entries {
        if names_another(Some(entry)) {
            failures.push(Failure::at(entry, "chain_id_mismatch"));
        }
    }
    if names_another(bundle.get("anchor")) {
        failures.push(Failure::chain_level("chain_id_mismatch"));
    }
}
