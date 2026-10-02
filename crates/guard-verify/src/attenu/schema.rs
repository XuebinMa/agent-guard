//! Whole-record validation for Attenu ledger entries.
//!
//! Integrity only proves that the producer committed to these bytes. It does
//! not prove this verifier understood them. Every accepted entry therefore
//! has to stay inside the published field vocabulary, and schema-v2 records
//! are validated before their values feed execution binding.

use serde_json::{Map, Value};

use super::{version, Failure};

const LEDGER_FIELDS: [&str; 39] = [
    "adapter",
    "agent",
    "authority",
    "authorized_params_hash",
    "body_state",
    "c14n",
    "call_id",
    "capture",
    "chain_id",
    "context",
    "detail",
    "disposition",
    "duration_ms",
    "error_code",
    "event",
    "granted",
    "hash",
    "invoked_params_hash",
    "mode",
    "node",
    "params_hash_reason",
    "params_salt",
    "parent",
    "pending_at_kill",
    "policy",
    "prev_hash",
    "reason",
    "reasons",
    "receipt",
    "requested",
    "revoked",
    "scope",
    "seq",
    "strikes",
    "target",
    "task",
    "tool",
    "ts",
    "v",
];

const V2_ONLY_FIELDS: [&str; 12] = [
    "adapter",
    "authorized_params_hash",
    "body_state",
    "call_id",
    "capture",
    "duration_ms",
    "error_code",
    "invoked_params_hash",
    "params_hash_reason",
    "params_salt",
    "pending_at_kill",
    "receipt",
];

const KNOWN_EVENTS: [&str; 8] = [
    "root",
    "spawn",
    "spawn_denied",
    "allow",
    "deny",
    "outcome",
    "done",
    "kill",
];

const ALLOW_ONLY_FIELDS: [&str; 5] = [
    "capture",
    "adapter",
    "authorized_params_hash",
    "params_hash_reason",
    "policy",
];

const CAPTURE_VALUES: [&str; 4] = [
    "wrapper_sync",
    "wrapper_async",
    "framework_post_hook",
    "pre_hook_only",
];

const BODY_STATES: [&str; 4] = ["returned", "raised", "abandoned", "deferred"];

/// Validate every entry under the bundle's declared schema version.
pub fn check_entry_schemas(
    entries: &[Value],
    schema_version: Option<i64>,
    failures: &mut Vec<Failure>,
) {
    for entry in entries {
        let Some(object) = entry.as_object() else {
            failures.push(Failure::at(entry, "invalid_ledger_entry"));
            continue;
        };

        if object
            .keys()
            .any(|field| !LEDGER_FIELDS.contains(&field.as_str()))
        {
            failures.push(Failure::at(entry, "unknown_ledger_fields"));
        }

        let event = object.get("event").and_then(Value::as_str);
        if !event.is_some_and(|event| KNOWN_EVENTS.contains(&event)) {
            failures.push(Failure::at(entry, "unknown_ledger_event"));
            continue;
        }

        if schema_version == Some(version::V1) {
            if object
                .keys()
                .any(|field| V2_ONLY_FIELDS.contains(&field.as_str()))
            {
                failures.push(Failure::at(entry, "v2_field_on_v1"));
            }
            continue;
        }

        if schema_version != Some(version::V2) {
            continue;
        }

        let reason = match event {
            Some("root") => validate_root(object).err().map(|_| "invalid_root"),
            Some("kill") => validate_kill(object).err().map(|_| "invalid_kill"),
            Some("allow") => validate_allow(object).err().map(|_| "invalid_allow"),
            Some("deny") => validate_deny(object).err().map(|_| "invalid_deny"),
            Some("outcome") => validate_outcome(object).err().map(|_| "invalid_outcome"),
            _ => None,
        };
        if let Some(reason) = reason {
            failures.push(Failure::at(entry, reason));
        }
    }
}

fn validate_root(entry: &Map<String, Value>) -> Result<(), ()> {
    required_hex(entry, "params_salt", 32)
}

fn validate_kill(entry: &Map<String, Value>) -> Result<(), ()> {
    let Some(value) = entry.get("pending_at_kill") else {
        return Ok(());
    };
    let pending = value.as_array().ok_or(())?;
    if pending.iter().all(|call_id| {
        call_id
            .as_str()
            .is_some_and(|call_id| valid_hex(call_id, 32))
    }) {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_allow(entry: &Map<String, Value>) -> Result<(), ()> {
    required_hex(entry, "call_id", 32)?;
    let capture = required_string(entry, "capture")?;
    if !CAPTURE_VALUES.contains(&capture) {
        return Err(());
    }

    let adapter = entry.get("adapter").and_then(Value::as_object).ok_or(())?;
    for member in ["module", "version", "hook_path"] {
        required_string(adapter, member)?;
    }

    if entry
        .get("policy")
        .is_some_and(|value| value.as_str() != Some("unlisted"))
    {
        return Err(());
    }
    optional_hash_and_reason(entry, "authorized_params_hash")
}

fn validate_deny(entry: &Map<String, Value>) -> Result<(), ()> {
    required_hex(entry, "call_id", 32)?;
    if entry
        .keys()
        .any(|field| ALLOW_ONLY_FIELDS.contains(&field.as_str()))
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_outcome(entry: &Map<String, Value>) -> Result<(), ()> {
    required_hex(entry, "call_id", 32)?;
    let body_state = required_string(entry, "body_state")?;
    if !BODY_STATES.contains(&body_state) {
        return Err(());
    }

    match (body_state, entry.get("error_code")) {
        ("raised", Some(Value::String(code))) if !code.is_empty() => {}
        ("raised", _) => return Err(()),
        (_, None) => {}
        (_, Some(_)) => return Err(()),
    }

    if entry.get("duration_ms").and_then(Value::as_u64).is_none() {
        return Err(());
    }
    optional_hash_and_reason(entry, "invoked_params_hash")?;

    if let Some(receipt) = entry.get("receipt") {
        let receipt = receipt.as_object().ok_or(())?;
        required_string(receipt, "type")?;
        required_string(receipt, "ref")?;
        required_hex(receipt, "digest", 64)?;
    }
    Ok(())
}

fn optional_hash_and_reason(entry: &Map<String, Value>, hash_field: &str) -> Result<(), ()> {
    if let Some(value) = entry.get(hash_field) {
        if !value.as_str().is_some_and(|hash| valid_hex(hash, 64)) {
            return Err(());
        }
    }
    if let Some(reason) = entry.get("params_hash_reason") {
        if reason.as_str() != Some("unsupported") || entry.contains_key(hash_field) {
            return Err(());
        }
    }
    Ok(())
}

fn required_string<'a>(entry: &'a Map<String, Value>, field: &str) -> Result<&'a str, ()> {
    entry
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(())
}

fn required_hex(entry: &Map<String, Value>, field: &str, length: usize) -> Result<(), ()> {
    if required_string(entry, field).is_ok_and(|value| valid_hex(value, length)) {
        Ok(())
    } else {
        Err(())
    }
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_field_sets_have_no_overlap_mistakes() {
        assert!(V2_ONLY_FIELDS
            .iter()
            .all(|field| LEDGER_FIELDS.contains(field)));
        assert_eq!(LEDGER_FIELDS.len(), 39);
        assert_eq!(V2_ONLY_FIELDS.len(), 12);
    }
}
