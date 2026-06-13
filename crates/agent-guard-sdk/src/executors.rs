use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use agent_guard_core::{
    file_paths::resolve_tool_path,
    payload::{extract_bash_command as extract_core_bash_command, ExtractedPayload},
    DecisionCode, GuardDecision,
};
use agent_guard_sandbox::{SandboxError, SandboxOutput};
use serde::Deserialize;

/// Adapt a decision-shaped payload error into `SandboxError::InvalidPayload`,
/// carrying the originating `DecisionCode` so callers can distinguish, e.g.,
/// a missing field from malformed JSON without parsing the message string.
fn invalid_payload_from_decision(decision: GuardDecision) -> SandboxError {
    match decision {
        GuardDecision::Deny { reason } | GuardDecision::AskUser { reason, .. } => {
            SandboxError::InvalidPayload {
                code: reason.code,
                message: reason.message,
            }
        }
        // The core extractors never return `Allow`, so this is unreachable today.
        // Fail closed with a generic invalid-payload code rather than panic if
        // that invariant ever changes. (Pre-1.0 cleanup, issue #61 item 3.)
        GuardDecision::Allow => SandboxError::InvalidPayload {
            code: DecisionCode::InvalidPayload,
            message: "core extractor returned an Allow decision with no value".to_string(),
        },
    }
}

pub(crate) fn extract_bash_command_for_execution(payload: &str) -> Result<String, SandboxError> {
    match extract_core_bash_command(payload) {
        Ok(ExtractedPayload::Command(command)) => Ok(command),
        Ok(_) => Err(SandboxError::InvalidPayload {
            code: DecisionCode::InvalidPayload,
            message: "unexpected payload variant while extracting bash command".to_string(),
        }),
        // Execution reuses the core payload parser, then adapts its decision-shaped
        // errors. The core extractor only emits these for payload problems (invalid
        // JSON, missing `command` field), so they map to `InvalidPayload` with the
        // originating code preserved, not a failed run.
        Err(decision) => Err(invalid_payload_from_decision(decision)),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct WriteFileRequest {
    path: String,
    content: String,
    #[serde(default)]
    append: bool,
}

pub(crate) fn execute_write_file(
    payload: &str,
    working_directory: Option<&Path>,
) -> Result<SandboxOutput, SandboxError> {
    let request: WriteFileRequest =
        serde_json::from_str(payload).map_err(|_| SandboxError::InvalidPayload {
            code: DecisionCode::InvalidPayload,
            message: "invalid payload JSON".to_string(),
        })?;
    let resolved_path = resolve_tool_path(&request.path, working_directory)
        .map_err(invalid_payload_from_decision)?;

    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    if request.append {
        options.append(true);
    } else {
        options.truncate(true);
    }

    let mut file = options.open(&resolved_path).map_err(|e| {
        SandboxError::ExecutionFailed(format!("failed to open file for write: {e}"))
    })?;
    file.write_all(request.content.as_bytes())
        .map_err(|e| SandboxError::ExecutionFailed(format!("failed to write file content: {e}")))?;

    Ok(SandboxOutput {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct HttpRequestExecution {
    method: Option<String>,
    url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    body: Option<String>,
}

const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn execute_http_request(payload: &str) -> Result<SandboxOutput, SandboxError> {
    let request: HttpRequestExecution =
        serde_json::from_str(payload).map_err(|_| SandboxError::InvalidPayload {
            code: DecisionCode::InvalidPayload,
            message: "invalid payload JSON".to_string(),
        })?;

    let url = reqwest::Url::parse(&request.url).map_err(|e| SandboxError::InvalidPayload {
        code: DecisionCode::InvalidPayload,
        message: format!("invalid URL: {e}"),
    })?;
    let (pin_host, pin_addr) = resolve_url_to_safe_addr(&url)?;

    let method = request
        .method
        .as_deref()
        .unwrap_or("GET")
        .parse::<reqwest::Method>()
        .map_err(|e| SandboxError::ExecutionFailed(format!("invalid HTTP method: {e}")))?;

    if !is_mutation_method(&method) {
        return Err(SandboxError::ExecutionFailed(format!(
            "HTTP method '{method}' is not supported for owned execution; use mutation methods only"
        )));
    }

    let headers = request.headers;
    let body = request.body;

    let handle = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(HTTP_REQUEST_TIMEOUT)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&pin_host, pin_addr)
            .build()
            .map_err(|e| {
                SandboxError::ExecutionFailed(format!("failed to build HTTP client: {e}"))
            })?;

        let mut builder = client.request(method, url);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }

        let response = builder
            .send()
            .map_err(|e| SandboxError::ExecutionFailed(format!("HTTP request failed: {e}")))?;
        let status = response.status();
        let resp_body = response.text().map_err(|e| {
            SandboxError::ExecutionFailed(format!("failed to read HTTP response body: {e}"))
        })?;

        Ok(SandboxOutput {
            exit_code: if status.is_success() { 0 } else { 1 },
            stdout: resp_body,
            stderr: String::new(),
        })
    });

    handle
        .join()
        .map_err(|_| SandboxError::ExecutionFailed("HTTP execution thread panicked".to_string()))?
}

/// Unconditional deny-list for resolved destination IPs. Covers categories
/// a URL regex cannot reliably catch after DNS:
///
///   * loopback (`127.0.0.0/8`, `::1`) — services bound to the host's
///     loopback interface are not meant for cross-process callers.
///   * link-local (`169.254.0.0/16`, `fe80::/10`) — cloud-provider
///     metadata endpoints and other auto-configuration targets.
///   * RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) — the
///     three "private use" IPv4 ranges that host internal services
///     (Consul, k8s API, internal RPCs).
///   * IPv6 unique-local-address (`fc00::/7`, per RFC 4193) — the IPv6
///     analogue of RFC1918.
///   * unspecified / broadcast / multicast — not meaningful destinations
///     for an outbound mutation HTTP call.
///
/// The previous design left loopback and RFC1918 out of this list and
/// expected operators to assemble per-deployment deny patterns; the
/// 2026-05-15 audit showed that broad allow-lists silently re-opened
/// SSRF to internal targets. The new default is fail-closed; future
/// work can add an explicit `allow_private_targets` policy opt-in for
/// users that genuinely intend the executor to reach internal services.
pub(crate) fn is_always_blocked_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_private()
                || is_v4_shared_or_benchmark(v4)
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`),
            // and NAT64 (`64:ff9b::a.b.c.d`) carry an embedded IPv4 that
            // dual-stack hosts route to the IPv4 endpoint. Recurse so the
            // same deny-list applies. Closes 2026-05-25 HIGH.
            if let Some(v4) = ipv6_extract_embedded_ipv4(v6) {
                return is_always_blocked_ip(&IpAddr::V4(v4));
            }
            v6.is_unspecified()
                || v6.is_multicast()
                || is_ipv6_link_local(v6)
                || is_ipv6_unique_local(v6)
        }
    }
}

/// IPv4 ranges that `std`'s helpers do not cover but that must never be
/// reachable from the outbound HTTP executor:
///   * `100.64.0.0/10` — RFC 6598 shared/CGNAT space, routed to internal
///     services and proxies in some cloud/ISP environments.
///   * `198.18.0.0/15` — RFC 2544 benchmarking range.
///   * `0.0.0.0/8` — RFC 1122 "this network"; `is_unspecified()` only catches
///     the single `0.0.0.0` address, not the whole block.
///
/// Closes 2026-06-01 MEDIUM (SSRF deny-list gap).
fn is_v4_shared_or_benchmark(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
        || o[0] == 0 // 0.0.0.0/8
}

pub(crate) fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// IPv6 unique-local-address range (RFC 4193): `fc00::/7`. Covers both
/// `fc00:`/`fcff:` and `fd00:`/`fdff:` prefixes. Stable `Ipv6Addr::is_unique_local`
/// is still unstable in `std`, so the bit test is inlined here.
pub(crate) fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Pull the embedded IPv4 out of an IPv6 address that carries one. Covers:
///   * IPv4-mapped (`::ffff:0:0/96`, RFC 4291 §2.5.5.2) — modern dual-stack.
///   * IPv4-compatible (`::/96` with non-zero low 32 bits, RFC 4291 §2.5.5.1)
///     — deprecated but still accepted by some stacks.
///   * NAT64 well-known prefix (`64:ff9b::/96`, RFC 6052) — IPv6-only-to-v4
///     translation path used by ISPs and 464XLAT clients.
///
/// `Ipv6Addr::to_ipv4()` already covers the first two but on `::` returns
/// `Some(0.0.0.0)`, which round-trips into the unspecified branch correctly,
/// and on `::1` is unreachable here because the top-level `is_loopback()`
/// check catches it before the IPv6 branch runs.
pub(crate) fn ipv6_extract_embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4() {
        return Some(v4);
    }
    let segments = v6.segments();
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6].iter().all(|&s| s == 0) {
        return Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        ));
    }
    // 6to4 (`2002::/16`, RFC 3056): the embedded IPv4 is the two segments after
    // the `2002` prefix, so `2002:AABB:CCDD::/48` carries `AA.BB.CC.DD`.
    // Closes 2026-06-01 MEDIUM (embedded-private 6to4 SSRF gap).
    if segments[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        ));
    }
    None
}

/// Resolve a URL's host once at policy time and return a host/address pair
/// suitable for pinning the reqwest client via `ClientBuilder::resolve`.
/// Rejects if any resolved address falls in the unconditional deny-list,
/// which closes the DNS-rebinding TOCTOU window by forcing reqwest to
/// connect to the vetted address.
pub(crate) fn resolve_url_to_safe_addr(
    url: &reqwest::Url,
) -> Result<(String, SocketAddr), SandboxError> {
    let host = url
        .host_str()
        .ok_or_else(|| SandboxError::ExecutionFailed("URL has no host".to_string()))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        SandboxError::ExecutionFailed(format!("URL '{url}' has no port and no known default"))
    })?;

    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            SandboxError::ExecutionFailed(format!("DNS resolution failed for '{host}': {e}"))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(SandboxError::ExecutionFailed(format!(
            "DNS resolution returned no addresses for '{host}'"
        )));
    }

    for addr in &addrs {
        if is_always_blocked_ip(&addr.ip()) {
            return Err(SandboxError::ExecutionFailed(format!(
                "URL host '{host}' resolves to blocked address {}",
                addr.ip()
            )));
        }
    }

    Ok((host.to_string(), addrs[0]))
}

/// Decide whether the SDK should own execution of this `HttpRequest`
/// payload (Execute path -- runs through `resolve_url_to_safe_addr` and
/// the SSRF deny-list) versus handing it off to the host (Handoff path
/// -- no SDK-side network guard). Returns `true` for mutation methods
/// (POST/PUT/PATCH/DELETE) and `true` whenever the method cannot be
/// proven non-mutation: parse failure, missing field, non-string field,
/// `null` root. The fail-closed branch closes the 2026-05-25-2 HIGH
/// silent-failure where a malformed payload routed to Handoff and
/// silently skipped the SSRF guard. Returns `false` only when parsing
/// succeeds and the method is one of the documented non-mutation
/// verbs (GET/HEAD/OPTIONS/...).
pub(crate) fn payload_declares_mutation_http(payload: &str) -> bool {
    let method = match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(v) => v
            .get("method")
            .and_then(|m| m.as_str())
            .map(|s| s.to_ascii_uppercase()),
        Err(err) => {
            tracing::warn!(
                target: "agent_guard::executors",
                error = %err,
                "HttpRequest payload failed to parse; failing closed to SDK Execute path"
            );
            return true;
        }
    };

    match method.as_deref() {
        Some("POST") | Some("PUT") | Some("PATCH") | Some("DELETE") => true,
        Some(_) => false,
        None => {
            tracing::warn!(
                target: "agent_guard::executors",
                "HttpRequest payload has no string `method` field; failing closed to SDK Execute path"
            );
            true
        }
    }
}

pub(crate) fn is_mutation_method(method: &reqwest::Method) -> bool {
    matches!(
        *method,
        reqwest::Method::POST
            | reqwest::Method::PUT
            | reqwest::Method::PATCH
            | reqwest::Method::DELETE
    )
}

#[cfg(test)]
mod tests {
    //! Regression coverage for the 2026-05-15 HIGH SSRF finding: the
    //! mutation HTTP executor's `is_always_blocked_ip` did not deny
    //! loopback, RFC1918, or IPv6 unique-local-address (fc00::/7), so a
    //! resolved-then-pinned URL could reach internal services (Consul,
    //! k8s API, cloud metadata neighbours, lab subnets) from a code path
    //! that markets itself as "safe outbound HTTP".
    use super::is_always_blocked_ip;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("parse IP")
    }

    // ── blocked (newly enforced) ─────────────────────────────────────────────

    #[test]
    fn blocks_ipv4_loopback() {
        assert!(is_always_blocked_ip(&ip("127.0.0.1")));
        assert!(is_always_blocked_ip(&ip("127.255.255.254")));
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(is_always_blocked_ip(&ip("::1")));
    }

    #[test]
    fn blocks_rfc1918_ten_dot() {
        assert!(is_always_blocked_ip(&ip("10.0.0.1")));
        assert!(is_always_blocked_ip(&ip("10.255.255.255")));
    }

    #[test]
    fn blocks_rfc1918_one_seven_two() {
        assert!(is_always_blocked_ip(&ip("172.16.0.1")));
        assert!(is_always_blocked_ip(&ip("172.31.255.254")));
    }

    #[test]
    fn allows_just_outside_rfc1918_one_seven_two_range() {
        // 172.15.x.x and 172.32.x.x are NOT RFC1918 — must remain reachable.
        assert!(!is_always_blocked_ip(&ip("172.15.0.1")));
        assert!(!is_always_blocked_ip(&ip("172.32.0.1")));
    }

    #[test]
    fn blocks_rfc1918_one_nine_two() {
        assert!(is_always_blocked_ip(&ip("192.168.1.1")));
        assert!(is_always_blocked_ip(&ip("192.168.255.255")));
    }

    #[test]
    fn blocks_ipv6_unique_local_fc00_slash_7() {
        // fc00::/7 covers fc00::..fdff:... — both fc-prefix and fd-prefix
        // are reserved as unique local addresses (RFC 4193).
        assert!(is_always_blocked_ip(&ip("fc00::1")));
        assert!(is_always_blocked_ip(&ip("fd00::1")));
        assert!(is_always_blocked_ip(&ip("fdff:ffff::1")));
    }

    // ── still blocked (regression-guard for the pre-existing categories) ────

    #[test]
    fn blocks_ipv4_link_local_carryover() {
        assert!(is_always_blocked_ip(&ip("169.254.169.254"))); // metadata
    }

    #[test]
    fn blocks_ipv6_link_local_carryover() {
        assert!(is_always_blocked_ip(&ip("fe80::1")));
    }

    #[test]
    fn blocks_unspecified_and_multicast_carryover() {
        assert!(is_always_blocked_ip(&ip("0.0.0.0")));
        assert!(is_always_blocked_ip(&ip("224.0.0.1")));
        assert!(is_always_blocked_ip(&ip("::")));
        assert!(is_always_blocked_ip(&ip("ff00::1")));
    }

    // ── allowed (public ranges must remain reachable) ───────────────────────

    #[test]
    fn allows_public_ipv4_addresses() {
        assert!(!is_always_blocked_ip(&ip("8.8.8.8")));
        assert!(!is_always_blocked_ip(&ip("1.1.1.1")));
        assert!(!is_always_blocked_ip(&ip("142.250.80.46")));
    }

    #[test]
    fn allows_public_ipv6_addresses() {
        assert!(!is_always_blocked_ip(&ip("2001:4860:4860::8888")));
        assert!(!is_always_blocked_ip(&ip("2606:4700:4700::1111")));
    }

    // ── 2026-05-25 HIGH: IPv4-mapped / -compatible / NAT64 IPv6 bypass ──────
    //
    // Dual-stack hosts route `::ffff:a.b.c.d` (IPv4-mapped, RFC 4291 §2.5.5.2)
    // and the deprecated `::a.b.c.d` (IPv4-compatible, §2.5.5.1) to the
    // embedded IPv4 endpoint. NAT64 (RFC 6052, well-known `64:ff9b::/96`)
    // does the same for IPv6-only stacks. The deny-list installed by 1a339da
    // only checked `Ipv6Addr::is_loopback()` (which matches `::1` strictly)
    // and the RFC 4193 unique-local prefix, so any of those wrapping forms
    // routed straight to loopback / RFC1918 / cloud-metadata.
    //
    // Fix recurses on the embedded IPv4 so the same deny-list applies.

    #[test]
    fn blocks_ipv4_mapped_loopback() {
        assert!(is_always_blocked_ip(&ip("::ffff:127.0.0.1")));
        assert!(is_always_blocked_ip(&ip("::ffff:127.255.255.254")));
    }

    #[test]
    fn blocks_ipv4_mapped_rfc1918() {
        assert!(is_always_blocked_ip(&ip("::ffff:10.0.0.1")));
        assert!(is_always_blocked_ip(&ip("::ffff:172.16.0.1")));
        assert!(is_always_blocked_ip(&ip("::ffff:192.168.1.1")));
    }

    #[test]
    fn blocks_ipv4_mapped_link_local_metadata() {
        assert!(is_always_blocked_ip(&ip("::ffff:169.254.169.254")));
    }

    #[test]
    fn blocks_ipv4_compatible_loopback() {
        // `::127.0.0.1` is the deprecated IPv4-compatible form — still
        // routes to 127.0.0.1 on dual-stack TCP, so must be blocked.
        assert!(is_always_blocked_ip(&ip("::127.0.0.1")));
    }

    #[test]
    fn blocks_nat64_well_known_metadata() {
        // 64:ff9b::169.254.169.254 — NAT64 path to cloud metadata.
        assert!(is_always_blocked_ip(&ip("64:ff9b::169.254.169.254")));
        assert!(is_always_blocked_ip(&ip("64:ff9b::10.0.0.1")));
        assert!(is_always_blocked_ip(&ip("64:ff9b::127.0.0.1")));
    }

    #[test]
    fn allows_ipv4_mapped_public_ipv4() {
        // `::ffff:8.8.8.8` is a wrapped public IPv4; recursion lands on
        // 8.8.8.8 which is allowed, so the wrapped form must also be.
        assert!(!is_always_blocked_ip(&ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn allows_nat64_to_public_ipv4() {
        // NAT64 is a legitimate v6-only-to-v4 translation path; the
        // wrapped IPv4 (`8.8.8.8`) is public, so the NAT64 form is OK.
        assert!(!is_always_blocked_ip(&ip("64:ff9b::8.8.8.8")));
    }

    // ── 2026-06-01 MEDIUM: SSRF deny-list gaps (CGNAT / benchmark /
    // this-network / 6to4) ─────────────────────────────────────────────────

    #[test]
    fn blocks_rfc6598_cgnat_shared_space() {
        // 100.64.0.0/10 spans the 100.64.x.x .. 100.127.x.x second octet.
        assert!(is_always_blocked_ip(&ip("100.64.0.1")));
        assert!(is_always_blocked_ip(&ip("100.100.0.1")));
        assert!(is_always_blocked_ip(&ip("100.127.255.254")));
    }

    #[test]
    fn allows_just_outside_cgnat_range() {
        // 100.63.x.x and 100.128.x.x are public — must remain reachable.
        assert!(!is_always_blocked_ip(&ip("100.63.255.255")));
        assert!(!is_always_blocked_ip(&ip("100.128.0.1")));
    }

    #[test]
    fn blocks_rfc2544_benchmark_range() {
        // 198.18.0.0/15 covers 198.18.x.x and 198.19.x.x.
        assert!(is_always_blocked_ip(&ip("198.18.0.1")));
        assert!(is_always_blocked_ip(&ip("198.19.255.254")));
        // 198.17.x.x and 198.20.x.x are outside the block.
        assert!(!is_always_blocked_ip(&ip("198.17.0.1")));
        assert!(!is_always_blocked_ip(&ip("198.20.0.1")));
    }

    #[test]
    fn blocks_this_network_zero_slash_eight() {
        // The whole 0.0.0.0/8 block, not just the unspecified 0.0.0.0.
        assert!(is_always_blocked_ip(&ip("0.1.2.3")));
        assert!(is_always_blocked_ip(&ip("0.255.255.255")));
    }

    #[test]
    fn blocks_6to4_embedded_private_ipv4() {
        // 2002:AABB:CCDD::/48 routes to embedded AA.BB.CC.DD on 6to4 stacks.
        // 2002:0a00:0001:: → 10.0.0.1 (RFC1918); 2002:a9fe:a9fe:: → metadata.
        assert!(is_always_blocked_ip(&ip("2002:0a00:0001::")));
        assert!(is_always_blocked_ip(&ip("2002:7f00:0001::"))); // 127.0.0.1
        assert!(is_always_blocked_ip(&ip("2002:a9fe:a9fe::"))); // 169.254.169.254
    }

    #[test]
    fn allows_6to4_to_public_ipv4() {
        // 2002:0808:0808:: → 8.8.8.8 (public) must stay reachable.
        assert!(!is_always_blocked_ip(&ip("2002:0808:0808::")));
    }

    // ── 2026-05-25-2 HIGH: payload_declares_mutation_http silent-failure ───
    //
    // Until this fix the function returned `false` on JSON parse failure
    // (or missing/non-string `method`), routing the call to
    // `RuntimeDecision::Handoff` instead of SDK-owned `Execute`. Handoff
    // skips `resolve_url_to_safe_addr`, so a malformed `HttpRequest`
    // payload that the policy somehow Allowed would bypass the SSRF guard
    // entirely. New posture: fail-closed -- when parsing can't prove the
    // method is non-mutation, treat it as mutation so the SDK owns it.

    use super::payload_declares_mutation_http;

    #[test]
    fn mutation_methods_return_true() {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let payload = format!(r#"{{"method":"{method}","url":"http://x"}}"#);
            assert!(
                payload_declares_mutation_http(&payload),
                "expected true for {method}"
            );
        }
    }

    #[test]
    fn mutation_methods_case_insensitive_return_true() {
        for method in ["post", "Put", "patch", "Delete"] {
            let payload = format!(r#"{{"method":"{method}","url":"http://x"}}"#);
            assert!(
                payload_declares_mutation_http(&payload),
                "expected true for {method}"
            );
        }
    }

    #[test]
    fn non_mutation_methods_return_false() {
        for method in ["GET", "HEAD", "OPTIONS"] {
            let payload = format!(r#"{{"method":"{method}","url":"http://x"}}"#);
            assert!(
                !payload_declares_mutation_http(&payload),
                "expected false for {method}"
            );
        }
    }

    #[test]
    fn malformed_json_fails_closed_to_true() {
        // Was the audit's exact bypass: parse-failure routed to Handoff.
        assert!(payload_declares_mutation_http("not valid json"));
        assert!(payload_declares_mutation_http("{"));
        assert!(payload_declares_mutation_http(""));
    }

    #[test]
    fn missing_method_field_fails_closed_to_true() {
        assert!(payload_declares_mutation_http(r#"{"url":"http://x"}"#));
    }

    #[test]
    fn non_string_method_fails_closed_to_true() {
        assert!(payload_declares_mutation_http(
            r#"{"method":123,"url":"http://x"}"#
        ));
        assert!(payload_declares_mutation_http(
            r#"{"method":null,"url":"http://x"}"#
        ));
        assert!(payload_declares_mutation_http(r#"{"method":["POST"]}"#));
    }

    #[test]
    fn empty_json_object_fails_closed_to_true() {
        assert!(payload_declares_mutation_http("{}"));
    }

    #[test]
    fn json_null_root_fails_closed_to_true() {
        // `null` parses successfully as serde_json::Value::Null, but has
        // no `method` field. The fail-closed path still applies.
        assert!(payload_declares_mutation_http("null"));
    }

    // ── pre-1.0 API cleanup: bad-request errors map to `InvalidPayload` ─────
    //
    // The three executors distinguish a malformed/incomplete request from a
    // failed execution by returning `SandboxError::InvalidPayload` (rather
    // than `ExecutionFailed`) when the payload cannot be parsed or is missing
    // the field the executor needs. `InvalidPayload` carries the originating
    // `DecisionCode` so callers can tell the categories apart programmatically.
    // These tests pin that contract so a future change cannot silently fold bad
    // requests back into `ExecutionFailed` or drop the code.

    use super::{execute_http_request, execute_write_file, extract_bash_command_for_execution};
    use agent_guard_core::DecisionCode;
    use agent_guard_sandbox::SandboxError;

    #[test]
    fn bash_extract_malformed_json_is_invalid_payload() {
        let err = extract_bash_command_for_execution("not valid json").unwrap_err();
        assert!(
            matches!(
                err,
                SandboxError::InvalidPayload {
                    code: DecisionCode::InvalidPayload,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn bash_extract_missing_command_carries_missing_field_code() {
        // The whole point of carrying the code: a missing `command` field is
        // `MissingPayloadField`, distinct from malformed JSON's `InvalidPayload`.
        let err = extract_bash_command_for_execution(r#"{"not_command":"echo hi"}"#).unwrap_err();
        match err {
            SandboxError::InvalidPayload { code, message } => {
                assert_eq!(code, DecisionCode::MissingPayloadField, "msg: {message}");
                assert!(
                    message.contains("command"),
                    "should mention command: {message}"
                );
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }

    #[test]
    fn write_file_malformed_json_is_invalid_payload() {
        let err = execute_write_file("not valid json", None).unwrap_err();
        assert!(
            matches!(err, SandboxError::InvalidPayload { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn http_request_malformed_json_is_invalid_payload() {
        let err = execute_http_request("not valid json").unwrap_err();
        assert!(
            matches!(err, SandboxError::InvalidPayload { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn http_request_invalid_url_is_invalid_payload() {
        // Valid JSON, but the URL cannot be parsed → bad request, not a failed run.
        let err = execute_http_request(r#"{"method":"POST","url":"not a url"}"#).unwrap_err();
        match err {
            SandboxError::InvalidPayload { message, .. } => {
                assert!(
                    message.contains("invalid URL"),
                    "should mention URL: {message}"
                );
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }
}
