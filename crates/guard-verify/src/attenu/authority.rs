//! Delegation monotonicity: a spawned node never holds more than its parent,
//! and an allowed scope was inside the acting node's own authority.
//!
//! Scope coverage: a pattern ending in `.*` covers any scope under that
//! prefix; every other pattern must match exactly.

use super::{entry_str, Failure};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct Authority {
    scopes: Vec<String>,
    constraints: HashMap<String, i64>,
    ttl: Option<i64>,
}

impl Authority {
    fn parse(value: &Value) -> Self {
        let scopes = value
            .get("scopes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let mut constraints = HashMap::new();
        if let Some(items) = value.get("constraints").and_then(Value::as_array) {
            for item in items {
                if let (Some(key), Some(max)) = (
                    item.get("key").and_then(Value::as_str),
                    item.get("max").and_then(Value::as_i64),
                ) {
                    constraints.insert(key.to_string(), max);
                }
            }
        }

        Authority {
            scopes,
            constraints,
            ttl: value.get("ttl").and_then(Value::as_i64),
        }
    }

    fn covers_scope(&self, scope: &str) -> bool {
        self.scopes
            .iter()
            .any(|pattern| scope_matches(pattern, scope))
    }

    /// Every granted scope is covered, every parent ceiling is present and no
    /// looser, and the lifetime does not extend past the parent's.
    fn contains(&self, child: &Authority) -> bool {
        if !child.scopes.iter().all(|scope| self.covers_scope(scope)) {
            return false;
        }
        for (key, parent_max) in &self.constraints {
            match child.constraints.get(key) {
                Some(child_max) if child_max <= parent_max => {}
                _ => return false,
            }
        }
        match (self.ttl, child.ttl) {
            (Some(parent_ttl), Some(child_ttl)) => child_ttl <= parent_ttl,
            (Some(_), None) => false,
            _ => true,
        }
    }
}

fn scope_matches(pattern: &str, scope: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => scope.starts_with(prefix),
        None => pattern == scope,
    }
}

/// Walk the ledger in order, tracking each node's authority as it is
/// established, and check every delegation and every allow against it.
///
/// The only `policy` value this format version defines.
const DEFINED_POLICY: &str = "unlisted";

/// Where `policy` may appear, and what it may say.
///
/// `policy` answers how an *allow* came to be, so on a `spawn`, `root`,
/// `outcome` or `deny` it means nothing and the entry is invalid. On an allow,
/// the only value v1 defines is `unlisted`.
///
/// This runs on every bundle rather than inside the execution-binding pass.
/// Binding is checked on `schema_version=2` chains only, so a `policy` check
/// living there never runs on a v1 chain — and every undefined value then buys
/// the containment exemption it should not have. The corpus README names that
/// as the mistake reference implementations have made.
pub fn check_policy_field(entries: &[Value], failures: &mut Vec<Failure>) {
    for entry in entries {
        let Some(policy) = entry.get("policy") else {
            continue;
        };
        if entry_str(entry, "event").as_deref() != Some("allow") {
            failures.push(Failure::at(entry, "policy_on_non_allow"));
        } else if policy.as_str() != Some(DEFINED_POLICY) {
            failures.push(Failure::at(entry, "invalid_allow"));
        }
    }
}

/// The corpus names the two failures these rules produce: `monotonicity` for
/// a delegation granting more than its parent holds, `containment` for an
/// allow authorizing a scope outside what the acting node was granted. Both
/// tokens come from the corpus rather than from this implementation — the
/// first revision to exercise containment had no such rows, so the names
/// here were placeholders until it did.
pub fn check_authority(entries: &[Value], failures: &mut Vec<Failure>) {
    let mut authorities: HashMap<String, Authority> = HashMap::new();

    for entry in entries {
        let node = entry_str(entry, "node").unwrap_or_default();
        match entry_str(entry, "event").as_deref() {
            Some("root") => {
                if let Some(authority) = entry.get("authority") {
                    authorities.insert(node, Authority::parse(authority));
                } else {
                    failures.push(Failure::at(entry, "unreadable_authority"));
                }
            }
            Some("spawn") => {
                let Some(granted) = entry.get("granted") else {
                    failures.push(Failure::at(entry, "unreadable_granted"));
                    continue;
                };
                let parent = entry_str(entry, "parent").unwrap_or_default();
                let Some(parent_authority) = authorities.get(&parent) else {
                    failures.push(Failure::at(entry, "unreadable_authority"));
                    continue;
                };
                let granted = Authority::parse(granted);
                if !parent_authority.contains(&granted) {
                    failures.push(Failure::at(entry, "monotonicity"));
                }
                authorities.insert(node, granted);
            }
            Some("allow") => {
                // A `policy`-marked allow records a call the adapter let
                // through without an authorization check. Its `scope` is a
                // label, not a claim of held authority, so there is nothing to
                // contain and testing it rejects an honest bundle.
                //
                // The exemption is earned by the one value the format defines,
                // never by the field being present: keying on presence lets a
                // marker anyone can write excuse an out-of-authority action,
                // which is the whole point of the row that pins it.
                if entry.get("policy").and_then(Value::as_str) == Some(DEFINED_POLICY) {
                    continue;
                }
                let Some(scope) = entry_str(entry, "scope") else {
                    continue;
                };
                match authorities.get(&node) {
                    Some(authority) if authority.covers_scope(&scope) => {}
                    Some(_) => failures.push(Failure::at(entry, "containment")),
                    None => failures.push(Failure::at(entry, "unreadable_authority")),
                }
            }
            _ => {}
        }
    }
}
