//! Execution binding: one authorization, one correctly ordered outcome, on
//! the same node, with the arguments that were authorized.

use super::{entry_str, Failure};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

struct AllowRecord {
    position: usize,
    node: String,
    authorized_params_hash: Option<String>,
}

/// A `call_id` is the only thing binding an authorization to the invocation
/// that followed it, so uniqueness is checked before any binding is attempted.
/// A collision is reported at the second sighting.
pub fn check_call_id_uniqueness(entries: &[Value], failures: &mut Vec<Failure>) {
    let mut seen: HashSet<String> = HashSet::new();
    for entry in entries {
        if entry_str(entry, "event").as_deref() != Some("allow") {
            continue;
        }
        let Some(call_id) = entry_str(entry, "call_id") else {
            continue;
        };
        if !seen.insert(call_id) {
            failures.push(Failure::at(entry, "duplicate_call_id"));
        }
    }
}

/// Bind every outcome to its authorization.
///
/// Returns the `call_id`s that were authorized but never observed to a
/// terminal state. Those are reported as an aggregate rather than a failure:
/// an unaccounted call weakens what the ledger proves, but it is not itself
/// evidence that a rule was broken.
pub fn check_execution_binding(entries: &[Value], failures: &mut Vec<Failure>) -> Vec<String> {
    let allows = collect_first_allows(entries);
    let mut observed: HashMap<String, usize> = HashMap::new();

    for (position, entry) in entries.iter().enumerate() {
        if entry_str(entry, "event").as_deref() != Some("outcome") {
            continue;
        }
        let Some(call_id) = entry_str(entry, "call_id") else {
            failures.push(Failure::at(entry, "outcome_without_allow"));
            continue;
        };

        if observed.contains_key(&call_id) {
            failures.push(Failure::at(entry, "duplicate_outcome"));
            continue;
        }
        observed.insert(call_id.clone(), position);

        let Some(allow) = allows.get(&call_id) else {
            failures.push(Failure::at(entry, "outcome_without_allow"));
            continue;
        };

        if allow.position > position {
            failures.push(Failure::at(entry, "outcome_before_allow"));
            continue;
        }

        if entry_str(entry, "node").unwrap_or_default() != allow.node {
            failures.push(Failure::at(entry, "outcome_node_mismatch"));
        }

        let invoked = entry_str(entry, "invoked_params_hash");
        if invoked != allow.authorized_params_hash {
            failures.push(Failure::at(entry, "params_mismatch"));
        }
    }

    // Sorted: a verification report that changes between runs cannot be
    // compared, and hash-map order would do exactly that.
    let mut unaccounted: Vec<String> = allows
        .into_iter()
        .filter(|(call_id, _)| !observed.contains_key(call_id))
        .map(|(call_id, _)| call_id)
        .collect();
    unaccounted.sort();
    unaccounted
}

/// Index allows by `call_id`, keeping the first sighting. A colliding second
/// allow is already reported by `check_call_id_uniqueness`; binding against
/// the first keeps the ambiguity from silently changing which record an
/// outcome is compared to.
fn collect_first_allows(entries: &[Value]) -> HashMap<String, AllowRecord> {
    let mut allows: HashMap<String, AllowRecord> = HashMap::new();
    for (position, entry) in entries.iter().enumerate() {
        if entry_str(entry, "event").as_deref() != Some("allow") {
            continue;
        }
        let Some(call_id) = entry_str(entry, "call_id") else {
            continue;
        };
        allows.entry(call_id).or_insert_with(|| AllowRecord {
            position,
            node: entry_str(entry, "node").unwrap_or_default(),
            authorized_params_hash: entry_str(entry, "authorized_params_hash"),
        });
    }
    allows
}
