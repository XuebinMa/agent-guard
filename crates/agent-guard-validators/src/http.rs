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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

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

    // A missing `url` is reported by the policy engine's own extraction.
    let url = match value
        .get("url")
        .and_then(|u| u.as_str())
        .map(parse_http_url)
    {
        Some(Ok(url)) => Some(url),
        Some(Err(reason)) => return ValidationResult::Block { reason },
        None => None,
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
        if name.eq_ignore_ascii_case("host") {
            if let Some(url) = &url {
                if !val.as_str().is_some_and(|host| names_url_host(host, url)) {
                    return ValidationResult::Block {
                        reason: format!(
                            "HTTP Host header {val} does not name the URL's host '{}'; the \
                             request would be routed to a destination no rule evaluated",
                            url.host_str().unwrap_or_default()
                        ),
                    };
                }
            }
            continue;
        }
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

/// Parse `url` the way an HTTP client does, and refuse what is not an
/// absolute `http`/`https` URL with a host.
///
/// Rules are written against URL text, and a scheme-less or non-HTTP string
/// matches none of them while a client may still resolve it somewhere.
fn parse_http_url(url: &str) -> Result<Url, String> {
    let parsed =
        Url::parse(url).map_err(|error| format!("URL {url:?} is not an absolute URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err(format!("URL {url:?} is not an http or https URL"));
    }
    Ok(parsed)
}

/// Whether a `Host` header value is the URL's own host, with or without the
/// port the URL would use.
fn names_url_host(header: &str, url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let with_port = url
        .port_or_known_default()
        .map(|port| format!("{host}:{port}"));
    header.eq_ignore_ascii_case(host)
        || with_port.is_some_and(|with_port| header.eq_ignore_ascii_case(&with_port))
}

/// Other spellings of `url` that name the same destination, for matching
/// policy rules against what a client would connect to as well as against
/// what was written.
///
/// Parsing lowercases the scheme and host, resolves numeric and
/// percent-encoded IPv4 forms to dotted decimal, turns backslashes into
/// slashes and drops surrounding whitespace. Two further forms follow from
/// it: the URL without userinfo, and an IPv6 literal that embeds an IPv4
/// address written as that IPv4 address. Returns nothing for a URL that does
/// not parse; [`validate_http_request`] refuses those.
pub fn canonical_url_subjects(url: &str) -> Vec<String> {
    let Ok(parsed) = Url::parse(url) else {
        return Vec::new();
    };
    let mut forms = vec![parsed.clone()];

    let mut bare = parsed;
    if bare.set_username("").is_ok() && bare.set_password(None).is_ok() {
        forms.push(bare.clone());
    }
    let embedded = match bare.host() {
        Some(Host::Ipv6(v6)) => embedded_ipv4(&v6),
        _ => None,
    };
    if let Some(v4) = embedded {
        if bare.set_ip_host(IpAddr::V4(v4)).is_ok() {
            forms.push(bare);
        }
    }

    let mut subjects: Vec<String> = Vec::new();
    for form in forms {
        let text = String::from(form);
        // `%61` is `a` to the server that receives it (RFC 3986 §2.3), so a
        // rule naming `/admin` has to see `/%61dmin` as `/admin`.
        for spelling in [decode_unreserved(&text), text] {
            if spelling != url && !subjects.contains(&spelling) {
                subjects.push(spelling);
            }
        }
    }
    subjects
}

/// `url` without its userinfo, when it has any.
///
/// Userinfo is the one spelling that changes which host a textual prefix
/// names: `https://allowed.example@other.example/` starts with an allowed
/// origin and goes somewhere else. An allow-list has to be asked about this
/// form as a request in its own right, not only as another spelling.
pub fn url_without_userinfo(url: &str) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    if parsed.username().is_empty() && parsed.password().is_none() {
        return None;
    }
    parsed.set_username("").ok()?;
    parsed.set_password(None).ok()?;
    Some(parsed.into())
}

/// Decode percent-escapes of unreserved characters (letters, digits, `-`,
/// `.`, `_`, `~`) and nothing else. One pass: `%2561` stays `%2561`, a
/// literal percent sign followed by `61`.
fn decode_unreserved(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = (bytes[index] == b'%')
            .then(|| text.get(index + 1..index + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            .filter(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(byte));
        match escaped {
            Some(byte) => {
                decoded.push(char::from(byte));
                index += 3;
            }
            None => {
                let ch = text[index..].chars().next().unwrap_or_default();
                decoded.push(ch);
                index += ch.len_utf8().max(1);
            }
        }
    }
    decoded
}

/// The IPv4 address an IPv6 address carries, when a dual-stack host would
/// route it to that IPv4 endpoint:
///   * IPv4-mapped (`::ffff:0:0/96`) and IPv4-compatible (`::/96`),
///   * NAT64 well-known prefix (`64:ff9b::/96`, RFC 6052),
///   * 6to4 (`2002::/16`, RFC 3056), whose next two segments are the address.
pub fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4() {
        return Some(v4);
    }
    let segments = v6.segments();
    let from_segments = |high: u16, low: u16| {
        Ipv4Addr::new(
            (high >> 8) as u8,
            (high & 0xff) as u8,
            (low >> 8) as u8,
            (low & 0xff) as u8,
        )
    };
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6].iter().all(|&s| s == 0) {
        return Some(from_segments(segments[6], segments[7]));
    }
    if segments[0] == 0x2002 {
        return Some(from_segments(segments[1], segments[2]));
    }
    None
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
