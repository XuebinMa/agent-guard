use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
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
                code: reason.code(),
                message: reason.message().to_string(),
            }
        }
        // The core extractors only deny or ask; `Allow` (and any future variant)
        // is unreachable today. Fail closed with a generic invalid-payload code
        // rather than panic if that invariant ever changes. (Issues #61, #42.)
        _ => SandboxError::InvalidPayload {
            code: DecisionCode::InvalidPayload,
            message: "core extractor returned a non-deny decision with no value".to_string(),
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

/// Filesystem authority supplied to the guard-owned WriteFile executor.
///
/// WorkspaceWrite must carry a concrete root; FullAccess is the only mode that
/// may intentionally opt out of confinement. Encoding that distinction as an
/// enum prevents an accidental `None` from meaning "allow the whole host".
pub(crate) enum WriteFileScope<'a> {
    Workspace(&'a Path),
    Unrestricted,
}

pub(crate) fn execute_write_file(
    payload: &str,
    scope: WriteFileScope<'_>,
) -> Result<SandboxOutput, SandboxError> {
    execute_write_file_with_pre_open(payload, scope, || {})
}

fn execute_write_file_with_pre_open(
    payload: &str,
    scope: WriteFileScope<'_>,
    pre_open: impl FnOnce(),
) -> Result<SandboxOutput, SandboxError> {
    let request: WriteFileRequest =
        serde_json::from_str(payload).map_err(|_| SandboxError::InvalidPayload {
            code: DecisionCode::InvalidPayload,
            message: "invalid payload JSON".to_string(),
        })?;

    match scope {
        WriteFileScope::Workspace(workspace) => {
            execute_workspace_write(&request, workspace, pre_open)?
        }
        WriteFileScope::Unrestricted => execute_unrestricted_write(&request, pre_open)?,
    }

    Ok(SandboxOutput {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

fn execute_workspace_write(
    request: &WriteFileRequest,
    workspace: &Path,
    pre_open: impl FnOnce(),
) -> Result<(), SandboxError> {
    let workspace_dir = cap_std::fs::Dir::open_ambient_dir(workspace, cap_std::ambient_authority())
        .map_err(|error| {
            SandboxError::ExecutionFailed(format!(
                "failed to open workspace root for WriteFile: {error}"
            ))
        })?;
    let relative_path = workspace_relative_path(&request.path, workspace)?;

    let mut options = cap_std::fs::OpenOptions::new();
    options.create(true).write(true);
    if request.append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(OPEN_WITHOUT_WAITING);
    }

    // Tests use this seam to deterministically replace a validated ancestor.
    // Production passes a no-op. The actual open remains relative to the
    // already-open workspace descriptor, so the hook cannot expand authority.
    pre_open();
    let file = workspace_dir
        .open_with(&relative_path, &options)
        .map_err(|error| {
            SandboxError::ExecutionFailed(format!(
                "failed to open workspace file for write: {error}"
            ))
        })?;
    require_regular_file(file.metadata().map(|metadata| metadata.is_file()))?;
    write_file_content(file, &request.content)
}

/// Opening a FIFO for writing waits for a reader, on the host's thread and
/// with no deadline. With this flag the open returns at once; the type check
/// after it then sees what was opened, not what a path named a moment ago.
#[cfg(unix)]
const OPEN_WITHOUT_WAITING: i32 = libc::O_NONBLOCK;

/// WriteFile writes files. A FIFO, device or socket an agent placed in its
/// workspace is something else reached through a file name.
fn require_regular_file(is_file: std::io::Result<bool>) -> Result<(), SandboxError> {
    match is_file {
        Ok(true) => Ok(()),
        Ok(false) => Err(SandboxError::ExecutionFailed(
            "refusing to write: the target is not a regular file".to_string(),
        )),
        Err(error) => Err(SandboxError::ExecutionFailed(format!(
            "failed to inspect the opened file: {error}"
        ))),
    }
}

fn execute_unrestricted_write(
    request: &WriteFileRequest,
    pre_open: impl FnOnce(),
) -> Result<(), SandboxError> {
    // FullAccess intentionally retains ambient filesystem authority. Keep its
    // existing resolution and std::fs open behaviour distinct from the
    // capability-relative WorkspaceWrite path.
    let resolved_path =
        resolve_tool_path(&request.path, None).map_err(invalid_payload_from_decision)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    if request.append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(OPEN_WITHOUT_WAITING);
    }

    pre_open();
    let file = options.open(&resolved_path).map_err(|error| {
        SandboxError::ExecutionFailed(format!("failed to open file for write: {error}"))
    })?;
    require_regular_file(file.metadata().map(|metadata| metadata.is_file()))?;
    write_file_content(file, &request.content)
}

fn write_file_content(mut file: impl Write, content: &str) -> Result<(), SandboxError> {
    file.write_all(content.as_bytes()).map_err(|error| {
        SandboxError::ExecutionFailed(format!("failed to write file content: {error}"))
    })
}

fn workspace_relative_path(raw_path: &str, workspace: &Path) -> Result<PathBuf, SandboxError> {
    if raw_path.trim().is_empty() {
        return Err(SandboxError::InvalidPayload {
            code: DecisionCode::InvalidPayload,
            message: "path must not be empty".to_string(),
        });
    }

    let path = Path::new(raw_path);
    if path.is_absolute() {
        let workspace = absolute_lexical_path(workspace)?;
        let requested = normalize_lexical_path(path);
        return requested
            .strip_prefix(&workspace)
            .map(Path::to_path_buf)
            .map_err(|_| workspace_path_escape(raw_path, &workspace));
    }

    normalize_relative_workspace_path(path)
        .ok_or_else(|| workspace_path_escape(raw_path, workspace))
}

fn absolute_lexical_path(path: &Path) -> Result<PathBuf, SandboxError> {
    if path.is_absolute() {
        return Ok(normalize_lexical_path(path));
    }

    let current_dir = std::env::current_dir().map_err(|error| {
        SandboxError::ExecutionFailed(format!(
            "failed to resolve relative workspace root: {error}"
        ))
    })?;
    Ok(normalize_lexical_path(&current_dir.join(path)))
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn normalize_relative_workspace_path(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn workspace_path_escape(raw_path: &str, workspace: &Path) -> SandboxError {
    SandboxError::InvalidPayload {
        code: DecisionCode::PathTraversal,
        message: format!(
            "path '{raw_path}' resolves outside the workspace ('{}')",
            workspace.display()
        ),
    }
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
const HTTP_RESPONSE_BODY_LIMIT: usize = 4 * 1024 * 1024;
const HTTP_EXECUTION_CONCURRENCY_LIMIT: usize = 64;
static HTTP_EXECUTION_LIMITER: HttpConcurrencyLimiter =
    HttpConcurrencyLimiter::new(HTTP_EXECUTION_CONCURRENCY_LIMIT);

struct HttpConcurrencyLimiter {
    in_flight: AtomicUsize,
    limit: usize,
}

impl HttpConcurrencyLimiter {
    const fn new(limit: usize) -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_acquire(&self) -> Result<HttpExecutionPermit<'_>, SandboxError> {
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return Err(SandboxError::ExecutionFailed(format!(
                    "HTTP execution concurrency limit of {} reached",
                    self.limit
                )));
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(HttpExecutionPermit { limiter: self }),
                Err(observed) => current = observed,
            }
        }
    }
}

struct HttpExecutionPermit<'a> {
    limiter: &'a HttpConcurrencyLimiter,
}

impl Drop for HttpExecutionPermit<'_> {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

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

    // Guard-owned HTTP is synchronous, but callers may invoke it from many
    // host threads at once. Reserve a bounded global slot before DNS/network
    // work so overload fails predictably instead of creating unbounded socket,
    // response-buffer and TLS state.
    let _permit = HTTP_EXECUTION_LIMITER.try_acquire()?;

    // Method support is decided before DNS or any other network-capable
    // operation. Extension methods take the owned fail-closed path, but an
    // unsupported verb must not turn the executor into a DNS oracle.
    let (pin_host, pin_addr) = resolve_url_to_safe_addr(&url)?;

    // This API is already synchronous. Running it directly avoids allocating
    // one unbounded OS thread per concurrent request; reqwest's request and
    // connect timeouts bound the blocking call itself.
    let client = build_pinned_http_client(&pin_host, pin_addr)?;
    let mut builder = client.request(method, url);
    for (name, value) in request.headers {
        builder = builder.header(name, value);
    }
    if let Some(body) = request.body {
        builder = builder.body(body);
    }

    let mut response = builder
        .send()
        .map_err(|e| SandboxError::ExecutionFailed(format!("HTTP request failed: {e}")))?;
    let status = response.status();
    let body = read_bounded_http_body(&mut response, HTTP_RESPONSE_BODY_LIMIT)?;
    let resp_body = String::from_utf8_lossy(&body).into_owned();

    Ok(SandboxOutput {
        exit_code: if status.is_success() { 0 } else { 1 },
        stdout: resp_body,
        stderr: String::new(),
    })
}

fn build_pinned_http_client(
    pin_host: &str,
    pin_addr: SocketAddr,
) -> Result<reqwest::blocking::Client, SandboxError> {
    reqwest::blocking::Client::builder()
        .timeout(HTTP_REQUEST_TIMEOUT)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // Environment proxies would receive the request instead of the
        // destination vetted and pinned above. Proxy use needs its own
        // trusted policy model, so the guarded executor disables it.
        .no_proxy()
        .resolve(pin_host, pin_addr)
        .build()
        .map_err(|e| SandboxError::ExecutionFailed(format!("failed to build HTTP client: {e}")))
}

fn read_bounded_http_body(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, SandboxError> {
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut body = Vec::with_capacity(limit.min(16 * 1024));
    reader
        .take(read_limit)
        .read_to_end(&mut body)
        .map_err(|e| {
            SandboxError::ExecutionFailed(format!("failed to read HTTP response body: {e}"))
        })?;
    if body.len() > limit {
        return Err(SandboxError::ExecutionFailed(format!(
            "HTTP response body exceeded the {limit}-byte limit"
        )));
    }
    Ok(body)
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
///
/// 6to4 (`2002::/16`, RFC 3056) is covered as well: `2002:AABB:CCDD::/48`
/// carries `AA.BB.CC.DD`. Closes 2026-06-01 MEDIUM.
///
/// The extraction itself lives with the URL canonicalisation in the
/// validators, so the decision and the executor cannot disagree about which
/// IPv6 literals name an IPv4 endpoint.
pub(crate) fn ipv6_extract_embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    agent_guard_validators::http::embedded_ipv4(v6)
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
/// (POST/PUT/PATCH/DELETE), extension/unsafe methods, and whenever the method
/// cannot be proven to be one of the explicitly supported handoff methods:
/// parse failure, missing field, non-string field, or `null` root. The
/// fail-closed branch closes the 2026-05-25-2 HIGH
/// silent-failure where a malformed payload routed to Handoff and
/// silently skipped the SSRF guard. Returns `false` only when parsing
/// succeeds and the method is one of the documented handoff verbs
/// (GET/HEAD/OPTIONS).
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
        Some("GET") | Some("HEAD") | Some("OPTIONS") => false,
        Some(_) => true,
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

    use super::{
        build_pinned_http_client, payload_declares_mutation_http, read_bounded_http_body,
        HttpConcurrencyLimiter,
    };
    use std::io::Cursor;
    use std::net::{SocketAddr, TcpListener};
    use std::process::Command;
    use std::time::{Duration, Instant};

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
    fn extension_and_unsafe_methods_fail_closed_to_owned_execution() {
        for method in ["TRACE", "CONNECT", "PROPFIND", "MKCOL", "PURGE", "CUSTOM"] {
            let payload = format!(r#"{{"method":"{method}","url":"http://x"}}"#);
            assert!(
                payload_declares_mutation_http(&payload),
                "unrecognized method {method} must not bypass the guarded executor"
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

    #[test]
    fn response_body_reader_accepts_the_limit_and_rejects_one_byte_more() {
        let mut exact = Cursor::new(vec![b'x'; 8]);
        assert_eq!(read_bounded_http_body(&mut exact, 8).unwrap().len(), 8);

        let mut oversized = Cursor::new(vec![b'x'; 9]);
        let error = read_bounded_http_body(&mut oversized, 8).unwrap_err();
        assert!(
            error.to_string().contains("exceeded the 8-byte limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn http_concurrency_budget_fails_fast_and_releases_slots() {
        let limiter = HttpConcurrencyLimiter::new(2);
        let first = limiter.try_acquire().expect("first slot");
        let second = limiter.try_acquire().expect("second slot");

        let error = match limiter.try_acquire() {
            Ok(_) => panic!("third slot must be refused"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("HTTP execution concurrency limit of 2 reached"));

        drop(first);
        let replacement = limiter.try_acquire().expect("released slot is reusable");
        drop(replacement);
        drop(second);
        assert_eq!(
            limiter.in_flight.load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    #[test]
    fn environment_proxy_cannot_bypass_the_vetted_pinned_destination() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind proxy sentinel");
        listener
            .set_nonblocking(true)
            .expect("set proxy sentinel nonblocking");
        let proxy_url = format!("http://{}", listener.local_addr().expect("proxy address"));

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "executors::tests::environment_proxy_probe_child",
                "--ignored",
                "--nocapture",
            ])
            .env("AGENT_GUARD_PROXY_PROBE_CHILD", "1")
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .spawn()
            .expect("spawn isolated proxy probe");

        let deadline = Instant::now() + Duration::from_secs(8);
        let mut contacted = false;
        let status = loop {
            match listener.accept() {
                Ok((_stream, _peer)) => contacted = true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("proxy sentinel failed: {error}"),
            }
            if let Some(status) = child.try_wait().expect("poll proxy probe") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("proxy probe did not finish before its deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        assert!(status.success(), "isolated proxy probe failed: {status}");
        assert!(
            !contacted,
            "an inherited proxy received a guarded request instead of the vetted destination"
        );
    }

    #[test]
    #[ignore = "runs only as the isolated child of the environment proxy regression"]
    fn environment_proxy_probe_child() {
        if std::env::var_os("AGENT_GUARD_PROXY_PROBE_CHILD").is_none() {
            return;
        }
        let pinned: SocketAddr = "203.0.113.1:9".parse().expect("TEST-NET address");
        let client =
            build_pinned_http_client("proxy-probe.invalid", pinned).expect("build guarded client");
        let result = client.post("http://proxy-probe.invalid:9/").send();
        assert!(result.is_err(), "TEST-NET endpoint unexpectedly responded");
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

    use super::{
        execute_http_request, execute_write_file, execute_write_file_with_pre_open,
        extract_bash_command_for_execution, WriteFileScope,
    };
    use agent_guard_core::DecisionCode;
    use agent_guard_sandbox::SandboxError;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

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
        let err = execute_write_file("not valid json", WriteFileScope::Unrestricted).unwrap_err();
        assert!(
            matches!(err, SandboxError::InvalidPayload { .. }),
            "got {err:?}"
        );
    }

    /// A FIFO is a file an agent can create in its own workspace. Opening one
    /// for writing waits for a reader that never has to come, on the host's
    /// thread and with no deadline, so only a regular file is written.
    #[cfg(unix)]
    #[test]
    fn write_file_refuses_a_fifo_instead_of_waiting_on_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().canonicalize().expect("workspace");
        let fifo = workspace.join("pipe");
        let c_path = std::ffi::CString::new(fifo.to_str().expect("UTF-8 path")).expect("path");
        // SAFETY: `c_path` is a valid NUL-terminated path inside the tempdir.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        for unrestricted in [false, true] {
            let (sender, receiver) = std::sync::mpsc::channel();
            let workspace = workspace.clone();
            let payload = serde_json::json!({
                "path": if unrestricted { fifo.to_str().unwrap() } else { "pipe" },
                "content": "x"
            })
            .to_string();
            let writer = std::thread::spawn(move || {
                let scope = if unrestricted {
                    WriteFileScope::Unrestricted
                } else {
                    WriteFileScope::Workspace(&workspace)
                };
                let _ = sender.send(execute_write_file(&payload, scope).map(|_| ()));
            });
            let outcome = receiver.recv_timeout(std::time::Duration::from_secs(2));
            // Attach a reader so a blocked writer always ends and the test
            // reports the failure rather than hanging on it.
            let reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .expect("open fifo reader");
            writer.join().expect("writer thread");
            drop(reader);

            let error = outcome
                .expect("the write must return instead of waiting for a reader")
                .expect_err("a FIFO is not a file to write");
            assert!(
                matches!(error, SandboxError::ExecutionFailed(_)),
                "got {error:?}"
            );
        }
    }

    /// A reader makes the FIFO open succeed even with O_NONBLOCK. This locks
    /// the opened-file type check itself, rather than only the no-reader open
    /// error: neither write scope may send bytes to the pipe.
    #[cfg(unix)]
    #[test]
    fn write_file_refuses_a_connected_fifo_without_writing_bytes() {
        use std::io::Read;

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().canonicalize().expect("workspace");
        let fifo = workspace.join("pipe");
        let c_path = std::ffi::CString::new(fifo.to_str().expect("UTF-8 path")).expect("path");
        // SAFETY: `c_path` is a valid NUL-terminated path inside the tempdir.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        for unrestricted in [false, true] {
            for append in [false, true] {
                let mut reader = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&fifo)
                    .expect("connect nonblocking fifo reader before the write");
                let (sender, receiver) = std::sync::mpsc::channel();
                let workspace = workspace.clone();
                let payload = serde_json::json!({
                    "path": if unrestricted { fifo.to_str().unwrap() } else { "pipe" },
                    "content": "fixture-marker",
                    "append": append
                })
                .to_string();
                let writer = std::thread::spawn(move || {
                    let scope = if unrestricted {
                        WriteFileScope::Unrestricted
                    } else {
                        WriteFileScope::Workspace(&workspace)
                    };
                    let _ = sender.send(execute_write_file(&payload, scope).map(|_| ()));
                });
                let outcome = receiver
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .expect("the connected FIFO write must return promptly");
                writer.join().expect("writer thread");

                let mut bytes = [0_u8; 32];
                match reader.read(&mut bytes) {
                    Ok(count) => assert_eq!(count, 0, "the refused write sent bytes to the FIFO"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("read the nonblocking FIFO: {error}"),
                }
                let error = outcome.expect_err("a connected FIFO is not a regular file");
                match error {
                    SandboxError::ExecutionFailed(message) => assert_eq!(
                        message,
                        "refusing to write: the target is not a regular file"
                    ),
                    other => panic!("expected an opened-file type refusal, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn workspace_write_still_creates_appends_and_truncates_regular_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().canonicalize().expect("workspace");
        let write = |content: &str, append: bool| {
            let payload =
                serde_json::json!({ "path": "notes.txt", "content": content, "append": append })
                    .to_string();
            execute_write_file(&payload, WriteFileScope::Workspace(&workspace)).expect("write");
            std::fs::read_to_string(workspace.join("notes.txt")).expect("read back")
        };
        assert_eq!(write("one", false), "one");
        assert_eq!(write("-two", true), "one-two");
        assert_eq!(write("three", false), "three");
    }

    #[test]
    fn workspace_write_rejects_absolute_escape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside.txt");
        std::fs::create_dir(&workspace).expect("workspace");
        let payload = serde_json::json!({ "path": outside, "content": "escaped" }).to_string();

        execute_write_file(&payload, WriteFileScope::Workspace(&workspace))
            .expect_err("an absolute path outside the workspace must fail closed");
        assert!(!outside.exists(), "absolute escape created an outside file");
    }

    #[test]
    fn workspace_write_rejects_parent_escape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside.txt");
        std::fs::create_dir(&workspace).expect("workspace");
        let payload = serde_json::json!({
            "path": "../outside.txt",
            "content": "escaped"
        })
        .to_string();

        execute_write_file(&payload, WriteFileScope::Workspace(&workspace))
            .expect_err("a parent traversal outside the workspace must fail closed");
        assert!(
            !outside.exists(),
            "parent traversal created an outside file"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn workspace_write_rejects_existing_symlink_escape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside.txt");
        let link = workspace.join("escape.txt");
        std::fs::create_dir(&workspace).expect("workspace");
        std::fs::write(&outside, "before").expect("seed outside file");
        symlink_for_write_test(&outside, &link);
        let payload = serde_json::json!({ "path": "escape.txt", "content": "after" }).to_string();

        execute_write_file(&payload, WriteFileScope::Workspace(&workspace))
            .expect_err("a symlink/reparse-point escape must fail closed");
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read outside file"),
            "before"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn workspace_write_rejects_symlink_installed_during_open() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside.txt");
        let target = workspace.join("target.txt");
        std::fs::create_dir(&workspace).expect("workspace");
        std::fs::write(&outside, "before").expect("seed outside file");
        let payload = serde_json::json!({ "path": "target.txt", "content": "after" }).to_string();

        let result = execute_write_file_with_pre_open(
            &payload,
            WriteFileScope::Workspace(&workspace),
            || symlink_for_write_test(&outside, &target),
        );

        result.expect_err("a symlink/reparse point installed during open must fail closed");
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read outside file"),
            "before"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn workspace_write_rejects_ancestor_replaced_after_validation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let ancestor = workspace.join("ancestor");
        let displaced_ancestor = workspace.join("ancestor-before-swap");
        let outside = temp.path().join("outside");
        let outside_file = outside.join("escaped.txt");
        std::fs::create_dir_all(&ancestor).expect("workspace ancestor");
        std::fs::create_dir(&outside).expect("outside dir");
        let payload = serde_json::json!({
            "path": "ancestor/escaped.txt",
            "content": "escaped"
        })
        .to_string();

        let result = execute_write_file_with_pre_open(
            &payload,
            WriteFileScope::Workspace(&workspace),
            || {
                // A separate thread performs the attacker-controlled swap in the
                // exact interval where the old executor had finished validating
                // the pathname but had not opened it yet.
                std::thread::scope(|scope| {
                    scope
                        .spawn(|| {
                            std::fs::rename(&ancestor, &displaced_ancestor)
                                .expect("displace ancestor");
                            symlink_for_write_test(&outside, &ancestor);
                        })
                        .join()
                        .expect("join ancestor-swap thread");
                });
            },
        );

        result.expect_err("an ancestor swap must not redirect a workspace write");
        assert!(
            !outside_file.exists(),
            "ancestor replacement redirected the write outside the workspace"
        );
    }

    #[test]
    fn full_access_write_remains_unrestricted() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("full-access.txt");
        let payload = serde_json::json!({ "path": target, "content": "allowed" }).to_string();

        execute_write_file(&payload, WriteFileScope::Unrestricted)
            .expect("FullAccess write should retain ambient filesystem authority");
        assert_eq!(
            std::fs::read_to_string(&target).expect("read FullAccess target"),
            "allowed"
        );
    }

    #[cfg(unix)]
    fn symlink_for_write_test(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).expect("create symlink");
    }

    #[cfg(windows)]
    fn symlink_for_write_test(target: &std::path::Path, link: &std::path::Path) {
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link).expect("create directory symlink");
        } else {
            std::os::windows::fs::symlink_file(target, link).expect("create file symlink");
        }
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
