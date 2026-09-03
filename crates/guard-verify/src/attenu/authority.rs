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
