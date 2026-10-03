//! Delegation monotonicity: a spawned node never holds more than its parent,
//! and an allowed scope was inside the acting node's own authority.
//!
//! Scope coverage: a pattern ending in `.*` covers any scope under that
//! prefix; every other pattern must match exactly.

use super::{entry_str, Failure};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Default)]
pub struct Authority {
    scopes: Vec<String>,
    constraints: HashMap<String, Constraint>,
    ttl: Option<i64>,
}

#[derive(Clone)]
enum Constraint {
    Max(f64),
    Rank(String),
    Allow(Vec<Value>),
    Deny(Vec<Value>),
    Prefix(String),
    /// An extension this verifier cannot interpret is never discarded. It
    /// can only be carried unchanged into a child; any difference fails the
    /// attenuation check closed.
    Opaque(Value),
}

impl Authority {
    fn parse(value: &Value) -> Result<Self, ()> {
        let object = value.as_object().ok_or(())?;
        if object
            .keys()
            .any(|key| !["scopes", "constraints", "ttl"].contains(&key.as_str()))
        {
            return Err(());
        }

        let scopes = match object.get("scopes") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().filter(|scope| valid_scope(scope)).ok_or(()))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(str::to_string)
                .collect(),
            Some(_) => return Err(()),
        };

        let mut constraints = HashMap::new();
        if let Some(value) = object.get("constraints") {
            let items = value.as_array().ok_or(())?;
            let mut seen = HashSet::new();
            for item in items {
                let (key, constraint) = parse_constraint(item)?;
                if !seen.insert(key.clone()) {
                    return Err(());
                }
                constraints.insert(key, constraint);
            }
        }

        let ttl = match object.get("ttl") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_i64().filter(|ttl| *ttl >= 0).ok_or(())?),
        };

        Ok(Authority {
            scopes,
            constraints,
            ttl,
        })
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
        for (key, parent_constraint) in &self.constraints {
            match child.constraints.get(key) {
                Some(child_constraint) if parent_constraint.contains(child_constraint) => {}
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

impl Constraint {
    fn contains(&self, child: &Constraint) -> bool {
        match (self, child) {
            (Constraint::Max(parent), Constraint::Max(child)) => child <= parent,
            (Constraint::Rank(parent), Constraint::Rank(child)) => rank_value(child)
                .is_some_and(|child| rank_value(parent).is_some_and(|parent| child <= parent)),
            (Constraint::Allow(parent), Constraint::Allow(child)) => {
                child.iter().all(|value| parent.contains(value))
            }
            (Constraint::Deny(parent), Constraint::Deny(child)) => {
                parent.iter().all(|value| child.contains(value))
            }
            (Constraint::Prefix(parent), Constraint::Prefix(child)) => child.starts_with(parent),
            (Constraint::Opaque(parent), Constraint::Opaque(child)) => parent == child,
            _ => false,
        }
    }
}

fn parse_constraint(value: &Value) -> Result<(String, Constraint), ()> {
    let object = value.as_object().ok_or(())?;
    let key = object
        .get("key")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .ok_or(())?
        .to_string();

    let kind = object.get("type").and_then(Value::as_str);
    let parsed = match kind {
        Some("allow") => {
            exact_members(
                object.keys().map(String::as_str),
                &["key", "type", "one_of", "field"],
            )?;
            validate_optional_field(object.get("field"))?;
            Constraint::Allow(
                object
                    .get("one_of")
                    .and_then(Value::as_array)
                    .cloned()
                    .ok_or(())?,
            )
        }
        Some("deny") => {
            exact_members(
                object.keys().map(String::as_str),
                &["key", "type", "not_one_of", "field"],
            )?;
            validate_optional_field(object.get("field"))?;
            Constraint::Deny(
                object
                    .get("not_one_of")
                    .and_then(Value::as_array)
                    .cloned()
                    .ok_or(())?,
            )
        }
        Some("prefix") => {
            exact_members(
                object.keys().map(String::as_str),
                &["key", "type", "prefix", "field"],
            )?;
            validate_optional_field(object.get("field"))?;
            Constraint::Prefix(
                object
                    .get("prefix")
                    .and_then(Value::as_str)
                    .ok_or(())?
                    .to_string(),
            )
        }
        Some("max_calls") => {
            exact_members(
                object.keys().map(String::as_str),
                &["key", "type", "max", "applies_to"],
            )?;
            if !object
                .get("applies_to")
                .and_then(Value::as_str)
                .is_some_and(valid_scope)
            {
                return Err(());
            }
            Constraint::Max(valid_number(object.get("max").ok_or(())?)?)
        }
        Some(_) => Constraint::Opaque(value.clone()),
        None if object.contains_key("max") => {
            exact_members(object.keys().map(String::as_str), &["key", "max"])?;
            Constraint::Max(valid_number(object.get("max").ok_or(())?)?)
        }
        None if object.contains_key("rank") => {
            exact_members(object.keys().map(String::as_str), &["key", "rank"])?;
            Constraint::Rank(
                object
                    .get("rank")
                    .and_then(Value::as_str)
                    .filter(|rank| rank_value(rank).is_some())
                    .ok_or(())?
                    .to_string(),
            )
        }
        None => Constraint::Opaque(value.clone()),
    };
    Ok((key, parsed))
}

fn exact_members<'a>(actual: impl Iterator<Item = &'a str>, allowed: &[&str]) -> Result<(), ()> {
    if actual.into_iter().all(|member| allowed.contains(&member)) {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_optional_field(value: Option<&Value>) -> Result<(), ()> {
    match value {
        None => Ok(()),
        Some(value) if value.as_str().is_some_and(|field| !field.is_empty()) => Ok(()),
        Some(_) => Err(()),
    }
}

fn valid_number(value: &Value) -> Result<f64, ()> {
    value
        .as_f64()
        .filter(|number| number.is_finite() && number.abs() <= 9_007_199_254_740_991.0)
        .ok_or(())
}

fn rank_value(value: &str) -> Option<u8> {
    match value {
        "none" => Some(0),
        "internal" => Some(1),
        "any" => Some(2),
        _ => None,
    }
}

fn valid_scope(scope: &str) -> bool {
    let mut segments = scope.split('.').peekable();
    let mut count = 0usize;
    while let Some(segment) = segments.next() {
        count += 1;
        if segment == "*" {
            return count >= 2 && segments.peek().is_none();
        }
        let mut chars = segment.chars();
        if !chars.next().is_some_and(|ch| ch.is_ascii_lowercase())
            || !chars
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
        {
            return false;
        }
    }
    count >= 2
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
///
/// The rule is version-independent; only the name differs. On a v2 chain the
/// v2 record check owns the entry and the format calls an undefined value
/// `invalid_allow`. A v1 chain has no record check, and the format calls it
/// `invalid_policy`.
pub fn check_policy_field(
    entries: &[Value],
    schema_version: Option<i64>,
    failures: &mut Vec<Failure>,
) {
    let undefined_value = if schema_version == Some(super::version::V1) {
        "invalid_policy"
    } else {
        "invalid_allow"
    };
    for entry in entries {
        let Some(policy) = entry.get("policy") else {
            continue;
        };
        if entry_str(entry, "event").as_deref() != Some("allow") {
            if schema_version == Some(super::version::V2)
                && entry_str(entry, "event").as_deref() == Some("deny")
            {
                // The v2 record schema reports this as `invalid_deny`.
                continue;
            }
            failures.push(Failure::at(entry, "policy_on_non_allow"));
        } else if schema_version == Some(super::version::V2) {
            // The v2 record schema reports this as `invalid_allow`.
            continue;
        } else if policy.as_str() != Some(DEFINED_POLICY) {
            failures.push(Failure::at(entry, undefined_value));
        }
    }
}

/// What the containment pass measured, for the report's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Measured {
    pub actions_checked: usize,
    pub ungated: usize,
}

/// The corpus names the two failures these rules produce: `monotonicity` for
/// a delegation granting more than its parent holds, `containment` for an
/// allow authorizing a scope outside what the acting node was granted. Both
/// tokens come from the corpus rather than from this implementation — the
/// first revision to exercise containment had no such rows, so the names
/// here were placeholders until it did.
///
/// A node the ledger never established holds no authority at all: an allow
/// by one is `containment`, as the README says, and a spawn from one grants
/// more than its parent holds. `unreadable_authority` is left to the one
/// place the README puts it, a root whose authority cannot be read.
///
/// The counts come from the same branch that decides what to measure, so
/// what is reported as checked is what was checked.
pub fn check_authority(entries: &[Value], failures: &mut Vec<Failure>) -> Measured {
    let mut authorities: HashMap<String, Authority> = HashMap::new();
    let mut measured = Measured::default();
    let no_authority = Authority::default();

    for entry in entries {
        let node = entry_str(entry, "node").unwrap_or_default();
        match entry_str(entry, "event").as_deref() {
            Some("root") => {
                if let Some(authority) = entry.get("authority") {
                    match Authority::parse(authority) {
                        Ok(authority) => {
                            authorities.insert(node, authority);
                        }
                        Err(()) => failures.push(Failure::at(entry, "unreadable_authority")),
                    }
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
                let parent_authority = authorities.get(&parent).unwrap_or(&no_authority);
                let Ok(granted) = Authority::parse(granted) else {
                    failures.push(Failure::at(entry, "unreadable_granted"));
                    continue;
                };
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
                    measured.ungated += 1;
                    continue;
                }
                let Some(scope) = entry_str(entry, "scope") else {
                    continue;
                };
                measured.actions_checked += 1;
                let authority = authorities.get(&node).unwrap_or(&no_authority);
                if !authority.covers_scope(&scope) {
                    failures.push(Failure::at(entry, "containment"));
                }
            }
            _ => {}
        }
    }
    measured
}
