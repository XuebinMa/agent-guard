#[cfg(target_os = "macos")]
use crate::SandboxOutput;
use crate::{
    RuntimeCheck, Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxResult,
};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::OnceLock;

/// macOS Seatbelt sandbox using sandbox-exec.
pub struct SeatbeltSandbox;

/// Escapes a string for interpolation inside a Scheme `"..."` string literal
/// in a Seatbelt profile.
///
/// # Contract
///
/// The output is **only safe when placed between `"` and `"` in the resulting
/// profile**. Callers MUST interpolate it inside a quoted string literal —
/// for example `(subpath "{}")`. Using the output as a bare token, an
/// unquoted symbol, or any other Scheme context is unsupported and unsafe.
///
/// # Safety properties (locked in by hardening tests below)
///
/// 1. `\` is escaped to `\\`, so it cannot start an unintended escape sequence.
/// 2. `"` is escaped to `\"`, so it cannot terminate the surrounding string.
/// 3. NUL and other control characters are rejected, so callers cannot
///    smuggle in characters that have implementation-defined meaning to
///    TinyScheme's reader.
///
/// Parentheses, semicolons, and other Scheme structural characters are
/// passed through unchanged because **inside a `"..."` literal they are
/// ordinary string content** — `)` does not close any S-expression and `;`
/// does not start a comment. The hardening tests below assert this for
/// realistic attack payloads.
#[cfg(any(target_os = "macos", test))]
fn escape_seatbelt_string(value: &str) -> Result<String, SandboxError> {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\0' => {
                return Err(SandboxError::ExecutionFailed(
                    "workspace path contains NUL byte, which cannot be encoded in a Seatbelt profile"
                        .to_string(),
                ));
            }
            ch if ch.is_control() => {
                return Err(SandboxError::ExecutionFailed(format!(
                    "workspace path contains unsupported control character U+{:04X}",
                    ch as u32
                )));
            }
            _ => escaped.push(ch),
        }
    }

    Ok(escaped)
}

fn unavailable_capabilities() -> SandboxCapabilities {
    SandboxCapabilities {
        filesystem_read_workspace: false,
        filesystem_read_global: false,
        filesystem_write_workspace: false,
        filesystem_write_global: false,
        network_outbound_any: false,
        network_outbound_internet: false,
        network_outbound_local: false,
        child_process_spawn: false,
        registry_write: false,
    }
}

#[cfg(target_os = "macos")]
fn seatbelt_runtime_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();

    *CACHE.get_or_init(|| {
        Command::new("sandbox-exec")
            .arg("-p")
            .arg("(version 1)\n(allow default)")
            .arg("/usr/bin/true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    })
}

#[cfg(not(target_os = "macos"))]
fn seatbelt_runtime_available() -> bool {
    false
}

impl Sandbox for SeatbeltSandbox {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn sandbox_type(&self) -> &'static str {
        "macos-seatbelt"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        if !seatbelt_runtime_available() {
            return unavailable_capabilities();
        }

        SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: true, // Seatbelt prototype currently allows global read
            filesystem_write_workspace: true,
            filesystem_write_global: false,
            network_outbound_any: false,
            network_outbound_internet: false,
            network_outbound_local: false,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    fn is_available(&self) -> bool {
        seatbelt_runtime_available()
    }

    fn availability_note(&self) -> Option<String> {
        if seatbelt_runtime_available() {
            Some("sandbox-exec runtime probe succeeded on this host".to_string())
        } else {
            Some("sandbox-exec is not functional on this macOS host".to_string())
        }
    }

    fn runtime_checks(&self) -> Vec<RuntimeCheck> {
        vec![if seatbelt_runtime_available() {
            RuntimeCheck::pass(
                "sandbox_exec_probe",
                "sandbox-exec successfully ran a minimal allow-all profile",
            )
        } else {
            RuntimeCheck::fail(
                "sandbox_exec_probe",
                "sandbox-exec could not execute a minimal allow-all profile on this host",
            )
        }]
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        #[cfg(target_os = "macos")]
        {
            if !seatbelt_runtime_available() {
                return Err(SandboxError::NotAvailable(
                    "sandbox-exec is not functional on this macOS host".to_string(),
                ));
            }

            let resolved_dir = context.working_directory.canonicalize().map_err(|e| {
                SandboxError::ExecutionFailed(format!("Failed to resolve workspace path: {}", e))
            })?;

            let escaped_workspace = escape_seatbelt_string(&resolved_dir.to_string_lossy())?;

            let profile = format!(
                r#"(version 1)
(deny default)
(allow file-read* (subpath "/"))
(allow file-write* (subpath "{}"))
(allow process-fork)
(allow process-exec)
(deny network*)"#,
                escaped_workspace
            );

            let mut child = Command::new("sandbox-exec")
                .arg("-p")
                .arg(profile)
                .arg("sh")
                .arg("-c")
                .arg(command)
                .current_dir(&context.working_directory)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| {
                    SandboxError::ExecutionFailed(format!("Failed to spawn sandbox-exec: {}", e))
                })?;

            // Handle timeout if specified
            if let Some(timeout_ms) = context.timeout_ms {
                use std::sync::mpsc;
                use std::thread;
                use std::time::Duration;

                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(timeout_ms));
                    let _ = tx.send(());
                });

                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let output = child
                                .wait_with_output()
                                .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;
                            return Ok(SandboxOutput {
                                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                                exit_code: status.code().unwrap_or(-1),
                            });
                        }
                        Ok(None) => {
                            if rx.try_recv().is_ok() {
                                let _ = child.kill();
                                let _ = child.wait(); // Prevent zombie
                                return Err(SandboxError::Timeout { ms: timeout_ms });
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => return Err(SandboxError::ExecutionFailed(e.to_string())),
                    }
                }
            }

            let output = child.wait_with_output().map_err(|e| {
                SandboxError::ExecutionFailed(format!(
                    "Failed to wait for sandboxed process: {}",
                    e
                ))
            })?;

            Ok(SandboxOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                exit_code: output.status.code().unwrap_or(-1),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = command;
            let _ = context;
            Err(SandboxError::NotAvailable(
                "Seatbelt is only available on macOS".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::escape_seatbelt_string;

    /// Reverses the documented escape: `\\` -> `\`, `\"` -> `"`. This is the
    /// minimum subset of TinyScheme string parsing needed to verify that the
    /// escaper is a faithful encoder for `"..."` interpolation.
    fn parse_back_scheme_string(escaped: &str) -> String {
        let mut out = String::with_capacity(escaped.len());
        let mut chars = escaped.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some(other) => {
                        // The escaper never produces other backslash escapes,
                        // so seeing one indicates an invariant violation.
                        panic!("unexpected escape sequence \\{other} in escaper output");
                    }
                    None => panic!("dangling backslash in escaper output"),
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn seatbelt_escape_keeps_normal_paths() {
        let escaped = escape_seatbelt_string("/tmp/agent-guard/workspace").unwrap();
        assert_eq!(escaped, "/tmp/agent-guard/workspace");
    }

    #[test]
    fn seatbelt_escape_escapes_quotes_and_backslashes() {
        let escaped = escape_seatbelt_string("/tmp/agent\"guard\\workspace").unwrap();
        assert_eq!(escaped, "/tmp/agent\\\"guard\\\\workspace");
    }

    #[test]
    fn seatbelt_escape_keeps_parentheses_as_plain_text() {
        let escaped = escape_seatbelt_string("/tmp/agent-guard (sandbox)").unwrap();
        assert_eq!(escaped, "/tmp/agent-guard (sandbox)");
    }

    #[test]
    fn seatbelt_escape_rejects_control_characters() {
        let error = escape_seatbelt_string("/tmp/agent-guard\nworkspace").unwrap_err();
        assert!(error.to_string().contains("control character"));
    }

    #[test]
    fn seatbelt_escape_keeps_unicode_and_paren_paths() {
        let payload = "/tmp/Documents (Backup)/项目/тест";
        let escaped = escape_seatbelt_string(payload).unwrap();
        assert_eq!(parse_back_scheme_string(&escaped), payload);
    }

    /// Hardening: a path that *tries* to close `(subpath "...")` and inject a
    /// new rule. The escaper must neutralize the closing quote so that
    /// TinyScheme parses the entire payload as one string.
    #[test]
    fn seatbelt_escape_neutralizes_subpath_close_attempt() {
        let payload = r#"/tmp/x") (allow file-write* (subpath "/"#;
        let escaped = escape_seatbelt_string(payload).unwrap();

        // Round-trip: parsing the escaped form back must yield the original.
        assert_eq!(parse_back_scheme_string(&escaped), payload);

        // Every `"` in the escaper output is preceded by `\` — no bare quote
        // can terminate the surrounding string literal.
        let mut prev = '\0';
        for ch in escaped.chars() {
            if ch == '"' {
                assert_eq!(prev, '\\', "bare quote leaked through escape: {escaped}");
            }
            prev = ch;
        }
    }

    /// Hardening: backslash + quote pair must not collapse into a
    /// quote-terminating sequence after escaping.
    #[test]
    fn seatbelt_escape_handles_backslash_quote_chain() {
        let payload = "\\\""; // literal `\` followed by `"`
        let escaped = escape_seatbelt_string(payload).unwrap();
        assert_eq!(escaped, r#"\\\""#);
        assert_eq!(parse_back_scheme_string(&escaped), payload);
    }

    /// Hardening: building the actual `(subpath "...")` form with an
    /// adversarial payload must yield a profile fragment that contains
    /// exactly one open and one close quote at the boundary positions.
    /// The literal text `(subpath` and `(allow` inside the payload is fine —
    /// it's part of the string content, not a parsed form.
    #[test]
    fn seatbelt_escape_full_subpath_form_has_balanced_unescaped_quotes() {
        let payload = r#"x") (allow file-read* (subpath "/etc"#;
        let escaped = escape_seatbelt_string(payload).unwrap();
        let profile = format!(r#"(allow file-write* (subpath "{}"))"#, escaped);

        let total_quotes = profile.chars().filter(|c| *c == '"').count();
        let escaped_quotes = profile.matches("\\\"").count();
        let unescaped = total_quotes - escaped_quotes;
        assert_eq!(
            unescaped, 2,
            "expected exactly two unescaped quotes (open + close) in: {profile}"
        );
    }
}
