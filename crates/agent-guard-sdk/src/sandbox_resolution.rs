//! Default sandbox resolution.
//!
//! Picks the strictest available OS-level sandbox backend for the current
//! target/feature combination, with a transparent diagnosis describing why a
//! given backend was chosen (or why the SDK fell back to `NoopSandbox`).

use agent_guard_sandbox::Sandbox;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DefaultSandboxDiagnosis {
    pub selected_name: &'static str,
    pub selected_sandbox_type: &'static str,
    pub fallback_to_noop: bool,
    pub reason: String,
}

/// Error for a by-name backend request that names a backend the SDK does not
/// know at all — distinct from a *known* backend that is not compiled in or
/// not functional on this host, which resolves to the truthful `"none"`
/// backend instead.
#[derive(Debug, thiserror::Error)]
#[error(
    "unknown sandbox backend '{requested}'; known backends: none, linux-seccomp, \
     linux-landlock, macos-seatbelt, windows-job-object, windows-appcontainer"
)]
pub struct UnknownBackendError {
    pub requested: String,
}

/// Truthful fallback shared by every by-name arm whose backend is not active
/// in this build/host: never claim isolation, always explain why.
fn by_name_fallback(requested: &str, why: &str) -> (Box<dyn Sandbox>, DefaultSandboxDiagnosis) {
    (
        Box::new(agent_guard_sandbox::NoopSandbox),
        DefaultSandboxDiagnosis {
            selected_name: "none",
            selected_sandbox_type: "none",
            fallback_to_noop: true,
            reason: format!(
                "requested backend '{requested}' is not active: {why}; resolving to the \
                 truthful 'none' backend rather than claiming isolation that is not present"
            ),
        },
    )
}

/// Resolve a sandbox backend by its `sandbox_type()` name (issue #100).
///
/// Accepted names (case-insensitive): `none`, `linux-seccomp`,
/// `linux-landlock`, `macos-seatbelt`, `windows-job-object`,
/// `windows-appcontainer`. The gating mirrors [`resolve_default_sandbox`]
/// exactly — in particular `linux-seccomp` is gated on the `seccomp` Cargo
/// feature (NOT on `SeccompSandbox::is_available()`, which is `true` on any
/// Linux host even when the unfiltered compat shell would run) — so a request
/// can never report isolation the build does not provide (GATE 5).
pub(crate) fn resolve_sandbox_by_name(
    name: &str,
) -> Result<(Box<dyn Sandbox>, DefaultSandboxDiagnosis), UnknownBackendError> {
    let requested = name.to_ascii_lowercase();
    match requested.as_str() {
        "none" => Ok((
            Box::new(agent_guard_sandbox::NoopSandbox),
            DefaultSandboxDiagnosis {
                selected_name: "none",
                selected_sandbox_type: "none",
                fallback_to_noop: false,
                reason: "the 'none' backend was explicitly requested".to_string(),
            },
        )),
        "linux-seccomp" => {
            #[cfg(all(target_os = "linux", feature = "seccomp"))]
            {
                Ok((
                    Box::new(agent_guard_sandbox::SeccompSandbox::new()),
                    DefaultSandboxDiagnosis {
                        selected_name: "seccomp",
                        selected_sandbox_type: "linux-seccomp",
                        fallback_to_noop: false,
                        reason:
                            "linux-seccomp was requested and the Seccomp-BPF filter is compiled in"
                                .to_string(),
                    },
                ))
            }
            #[cfg(not(all(target_os = "linux", feature = "seccomp")))]
            {
                Ok(by_name_fallback(
                    &requested,
                    "the 'seccomp' Cargo feature is not compiled into this build for this target",
                ))
            }
        }
        "linux-landlock" => {
            #[cfg(all(target_os = "linux", feature = "landlock"))]
            {
                let ll = agent_guard_sandbox::LandlockSandbox;
                if ll.is_available() {
                    Ok((
                        Box::new(ll),
                        DefaultSandboxDiagnosis {
                            selected_name: "landlock",
                            selected_sandbox_type: "linux-landlock",
                            fallback_to_noop: false,
                            reason: "linux-landlock was requested and Landlock is functional on this host".to_string(),
                        },
                    ))
                } else {
                    Ok(by_name_fallback(
                        &requested,
                        "Landlock is compiled in but not functional on this host",
                    ))
                }
            }
            #[cfg(not(all(target_os = "linux", feature = "landlock")))]
            {
                Ok(by_name_fallback(
                    &requested,
                    "the 'landlock' Cargo feature is not compiled into this build for this target",
                ))
            }
        }
        "macos-seatbelt" => {
            #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
            {
                let sb = agent_guard_sandbox::SeatbeltSandbox;
                if sb.is_available() {
                    Ok((
                        Box::new(sb),
                        DefaultSandboxDiagnosis {
                            selected_name: "seatbelt",
                            selected_sandbox_type: "macos-seatbelt",
                            fallback_to_noop: false,
                            reason: "macos-seatbelt was requested and sandbox-exec is functional on this host".to_string(),
                        },
                    ))
                } else {
                    Ok(by_name_fallback(
                        &requested,
                        "Seatbelt is compiled in but sandbox-exec is not functional on this host",
                    ))
                }
            }
            #[cfg(not(all(target_os = "macos", feature = "macos-sandbox")))]
            {
                Ok(by_name_fallback(
                    &requested,
                    "the 'macos-sandbox' Cargo feature is not compiled into this build for this target",
                ))
            }
        }
        "windows-job-object" => {
            #[cfg(all(target_os = "windows", feature = "windows-sandbox"))]
            {
                let sb = agent_guard_sandbox::JobObjectSandbox;
                if sb.is_available() {
                    Ok((
                        Box::new(sb),
                        DefaultSandboxDiagnosis {
                            selected_name: "JobObject",
                            selected_sandbox_type: "windows-job-object",
                            fallback_to_noop: false,
                            reason: "windows-job-object was requested and low-integrity process creation is functional".to_string(),
                        },
                    ))
                } else {
                    Ok(by_name_fallback(
                        &requested,
                        "Job Objects are compiled in but the low-integrity runtime is unavailable on this host",
                    ))
                }
            }
            #[cfg(not(all(target_os = "windows", feature = "windows-sandbox")))]
            {
                Ok(by_name_fallback(
                    &requested,
                    "the 'windows-sandbox' Cargo feature is not compiled into this build for this target",
                ))
            }
        }
        "windows-appcontainer" => {
            #[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
            {
                Ok((
                    Box::new(agent_guard_sandbox::AppContainerSandbox),
                    DefaultSandboxDiagnosis {
                        selected_name: "AppContainer",
                        selected_sandbox_type: "windows-appcontainer",
                        fallback_to_noop: false,
                        reason: "windows-appcontainer was requested and the feature is compiled in"
                            .to_string(),
                    },
                ))
            }
            #[cfg(not(all(target_os = "windows", feature = "windows-appcontainer")))]
            {
                Ok(by_name_fallback(
                    &requested,
                    "the 'windows-appcontainer' Cargo feature is not compiled into this build for this target",
                ))
            }
        }
        _ => Err(UnknownBackendError {
            requested: name.to_string(),
        }),
    }
}

/// Pick the default sandbox for the current platform/feature set, alongside a
/// diagnosis that callers (e.g. `guard-verify`, the doctor reports) can use to
/// explain the choice to operators.
pub(crate) fn resolve_default_sandbox() -> (Box<dyn Sandbox>, DefaultSandboxDiagnosis) {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "landlock")]
        {
            let ll = agent_guard_sandbox::LandlockSandbox;
            if ll.is_available() {
                return (
                    Box::new(ll),
                    DefaultSandboxDiagnosis {
                        selected_name: "landlock",
                        selected_sandbox_type: "linux-landlock",
                        fallback_to_noop: false,
                        reason: "Landlock is functional on this Linux host, so the SDK selects the stricter workspace-write backend.".to_string(),
                    },
                );
            }
        }
        // The native Seccomp-BPF filter only loads when the `seccomp` Cargo
        // feature is compiled in. Without it, `SeccompSandbox` silently runs an
        // unfiltered `sh -c` compatibility shell (see `linux.rs`
        // `execute_compat_shell`). Reporting that path as `selected="seccomp",
        // fallback_to_noop=false` would tell operators (and execution receipts,
        // which read `sandbox_type()`) that syscall isolation is active when it
        // is not — so split the diagnosis on the feature and fall back to a
        // truthful Noop backend when filtering is not actually present.
        #[cfg(feature = "seccomp")]
        {
            (
                Box::new(agent_guard_sandbox::SeccompSandbox::new()),
                DefaultSandboxDiagnosis {
                    selected_name: "seccomp",
                    selected_sandbox_type: "linux-seccomp",
                    fallback_to_noop: false,
                    reason: "Linux defaults to seccomp; the native Seccomp-BPF filter is compiled in and loads in the child before exec. Landlock is either disabled or unavailable on this host.".to_string(),
                },
            )
        }
        #[cfg(not(feature = "seccomp"))]
        {
            (
                Box::new(agent_guard_sandbox::NoopSandbox),
                DefaultSandboxDiagnosis {
                    selected_name: "none",
                    selected_sandbox_type: "none",
                    fallback_to_noop: true,
                    reason: "Neither Landlock nor the 'seccomp' Cargo feature is compiled in, so the SDK has no OS-level syscall isolation and runs an unfiltered compatibility shell. Rebuild with --features seccomp (with libseccomp present) or --features landlock to enable enforcement.".to_string(),
                },
            )
        }
    }
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    {
        let sb = agent_guard_sandbox::SeatbeltSandbox;
        if sb.is_available() {
            (
                Box::new(sb),
                DefaultSandboxDiagnosis {
                    selected_name: "seatbelt",
                    selected_sandbox_type: "macos-seatbelt",
                    fallback_to_noop: false,
                    reason: "Seatbelt runtime checks passed, so macOS execution uses the native sandbox backend.".to_string(),
                },
            )
        } else {
            (
                Box::new(agent_guard_sandbox::NoopSandbox),
                DefaultSandboxDiagnosis {
                    selected_name: "none",
                    selected_sandbox_type: "none",
                    fallback_to_noop: true,
                    reason: "Seatbelt support is enabled, but sandbox-exec is not functional on this host, so the SDK falls back to NoopSandbox.".to_string(),
                },
            )
        }
    }
    #[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
    {
        (
            Box::new(agent_guard_sandbox::AppContainerSandbox),
            DefaultSandboxDiagnosis {
                selected_name: "AppContainer",
                selected_sandbox_type: "windows-appcontainer",
                fallback_to_noop: false,
                reason: "The windows-appcontainer feature is enabled, so the SDK prefers AppContainer as the default Windows backend.".to_string(),
            },
        )
    }
    #[cfg(all(
        target_os = "windows",
        not(feature = "windows-appcontainer"),
        feature = "windows-sandbox"
    ))]
    {
        let sb = agent_guard_sandbox::JobObjectSandbox;
        if sb.is_available() {
            (
                Box::new(sb),
                DefaultSandboxDiagnosis {
                    selected_name: "JobObject",
                    selected_sandbox_type: "windows-job-object",
                    fallback_to_noop: false,
                    reason: "Low-integrity process creation is functional on this Windows host, so the SDK uses the Job Object backend.".to_string(),
                },
            )
        } else {
            (
                Box::new(agent_guard_sandbox::NoopSandbox),
                DefaultSandboxDiagnosis {
                    selected_name: "none",
                    selected_sandbox_type: "none",
                    fallback_to_noop: true,
                    reason: "The Windows low-integrity runtime is unavailable on this host, so the SDK falls back to NoopSandbox instead of pretending enforcement is active.".to_string(),
                },
            )
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "macos", feature = "macos-sandbox"),
        all(target_os = "windows", feature = "windows-appcontainer"),
        all(
            target_os = "windows",
            not(feature = "windows-appcontainer"),
            feature = "windows-sandbox"
        )
    )))]
    {
        (
            Box::new(agent_guard_sandbox::NoopSandbox),
            DefaultSandboxDiagnosis {
                selected_name: "none",
                selected_sandbox_type: "none",
                fallback_to_noop: true,
                reason: "No OS-level sandbox backend is enabled for this platform/build, so the SDK uses NoopSandbox.".to_string(),
            },
        )
    }
}
