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
/// a URL regex cannot reliably catch after DNS, including the link-local
/// range that hosts cloud-provider metadata services. Loopback and RFC1918
/// private ranges are intentionally not blocked here — those are policy
/// decisions the user expresses through `http_request.deny` URL patterns.
pub(crate) fn is_always_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()
        }
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast() || is_ipv6_link_local(v6),
    }
}

pub(crate) fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
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
