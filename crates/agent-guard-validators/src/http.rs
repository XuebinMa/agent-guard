//! HTTP request validator.
//!
//! Policy matching (agent-guard-core) is method-aware: a rule can deny e.g.
//! `POST` to a host while leaving `GET` allowed. The obvious way to smuggle a
//! mutation past such a rule is an HTTP *method-override* header — send a benign
//! `GET` with `X-HTTP-Method-Override: DELETE`, which many servers and
//! frameworks honour as a real `DELETE`. That would let the effective method
//! diverge from the method the policy engine evaluated.
//!
//! This validator runs before the policy decision (like the bash validator) and
//! blocks a request whose method-override header names a method different from
//! the declared one, so the effective method cannot escape method-based rules.

use crate::bash::ValidationResult;

/// Header names commonly honoured by servers/frameworks to override the method.
const METHOD_OVERRIDE_HEADERS: &[&str] = &[
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// Validate an `HttpRequest` payload for method-override smuggling.
///
/// `payload` is the raw JSON string (`{"url","method","headers","body"}`).
/// Returns [`ValidationResult::Block`] when a method-override header declares a
/// method that differs (case-insensitively) from the payload's declared method,
/// otherwise [`ValidationResult::Allow`]. A payload that is not valid JSON is
/// left to the policy engine (which fails it closed on its own); this validator
/// speaks only to the override-smuggling case.
pub fn validate_http_request(payload: &str) -> ValidationResult {
    let value: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => return ValidationResult::Allow,
    };

    let declared = value
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("GET");

    let headers = match value.get("headers").and_then(|h| h.as_object()) {
        Some(h) => h,
        None => return ValidationResult::Allow,
    };

    for (name, val) in headers {
        if !METHOD_OVERRIDE_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        if let Some(override_method) = val.as_str() {
            if !override_method.eq_ignore_ascii_case(declared) {
                return ValidationResult::Block {
                    reason: format!(
                        "HTTP method-override header '{}: {}' does not match the declared \
                         method '{}'; this can bypass method-based policy rules",
                        name, override_method, declared
                    ),
                };
            }
        }
    }

    ValidationResult::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_request_is_allowed() {
        let r = validate_http_request(r#"{"url":"https://x.test","method":"GET"}"#);
        assert!(matches!(r, ValidationResult::Allow));
    }

    #[test]
    fn no_headers_is_allowed() {
        let r = validate_http_request(r#"{"url":"https://x.test","method":"POST","body":"{}"}"#);
        assert!(matches!(r, ValidationResult::Allow));
    }

    #[test]
    fn matching_override_is_allowed() {
        // An override that names the same method is harmless.
        let r = validate_http_request(
            r#"{"url":"https://x.test","method":"POST","headers":{"X-HTTP-Method-Override":"POST"}}"#,
        );
        assert!(matches!(r, ValidationResult::Allow));
    }

    #[test]
    fn override_smuggling_delete_via_get_is_blocked() {
        let r = validate_http_request(
            r#"{"url":"https://x.test","method":"GET","headers":{"X-HTTP-Method-Override":"DELETE"}}"#,
        );
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn override_matching_is_case_insensitive_on_header_and_value() {
        let r = validate_http_request(
            r#"{"url":"https://x.test","method":"get","headers":{"x-method-override":"delete"}}"#,
        );
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn declared_method_defaults_to_get_when_absent() {
        // No declared method (defaults to GET) + override DELETE = smuggling.
        let r = validate_http_request(
            r#"{"url":"https://x.test","headers":{"X-HTTP-Method":"DELETE"}}"#,
        );
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn invalid_json_defers_to_policy() {
        let r = validate_http_request("not json");
        assert!(matches!(r, ValidationResult::Allow));
    }
}
