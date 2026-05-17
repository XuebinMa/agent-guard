use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use agent_guard_core::{
    file_paths::resolve_tool_path,
    payload::{extract_bash_command as extract_core_bash_command, ExtractedPayload},
    GuardDecision,
};
use agent_guard_sandbox::{SandboxError, SandboxOutput};
use serde::Deserialize;

pub(crate) fn extract_bash_command_for_execution(payload: &str) -> Result<String, SandboxError> {
    match extract_core_bash_command(payload) {
        Ok(ExtractedPayload::Command(command)) => Ok(command),
        Ok(_) => Err(SandboxError::ExecutionFailed(
            "unexpected payload variant while extracting bash command".to_string(),
        )),
        // Execution reuses the core payload parser, then adapts decision-shaped errors
        // into execution errors for the call sites that need a concrete command string.
        Err(GuardDecision::Deny { reason }) | Err(GuardDecision::AskUser { reason, .. }) => {
            Err(SandboxError::ExecutionFailed(reason.message))
        }
        Err(GuardDecision::Allow) => unreachable!("core bash extractor cannot return Allow"),
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
    let request: WriteFileRequest = serde_json::from_str(payload)
        .map_err(|_| SandboxError::ExecutionFailed("invalid payload JSON".to_string()))?;
    let resolved_path = resolve_tool_path(&request.path, working_directory)
        .map_err(|decision| SandboxError::ExecutionFailed(decision.to_string()))?;

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
    let request: HttpRequestExecution = serde_json::from_str(payload)
        .map_err(|_| SandboxError::ExecutionFailed("invalid payload JSON".to_string()))?;

    let url = reqwest::Url::parse(&request.url)
        .map_err(|e| SandboxError::ExecutionFailed(format!("invalid URL: {e}")))?;
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
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_multicast()
                || is_ipv6_link_local(v6)
                || is_ipv6_unique_local(v6)
        }
    }
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

pub(crate) fn payload_declares_mutation_http(payload: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| {
            v.get("method")
                .and_then(|m| m.as_str())
                .map(|s| s.to_ascii_uppercase())
        })
        .map(|method| matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"))
        .unwrap_or(false)
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
}
