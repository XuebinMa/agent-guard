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
        (
            Box::new(agent_guard_sandbox::SeccompSandbox::new()),
            DefaultSandboxDiagnosis {
                selected_name: "seccomp",
                selected_sandbox_type: "linux-seccomp",
                fallback_to_noop: false,
                reason: "Linux defaults to seccomp; Landlock is either disabled or unavailable on this host.".to_string(),
            },
        )
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
