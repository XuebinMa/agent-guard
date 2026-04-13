use agent_guard_sdk::{CapabilityDoctor, Guard, HealthStatus, RuntimeCheckStatus};

fn main() {
    println!("🛡️ agent-guard Demo 3: Platform Transparency (UCM Parity)");
    println!("====================================================\n");

    println!("The Unified Capability Model (UCM) ensures that security policies");
    println!("are platform-agnostic, while mapping them to optimal OS enforcers.\n");

    println!("👉 Action: Running CapabilityDoctor to inspect current host\n");

    let default = Guard::default_sandbox_diagnosis();
    println!("Default SDK sandbox resolution:");
    println!(
        "  - Selected: {} ({})",
        default.selected_name, default.selected_sandbox_type
    );
    println!(
        "  - Fallback: {}",
        if default.fallback_to_noop {
            "Yes"
        } else {
            "No"
        }
    );
    println!("  - Reason:   {}\n", default.reason);

    let reports = CapabilityDoctor::report();

    for report in reports {
        println!("--------------------------------------------------");
        println!("Sandbox: {} ({})", report.name, report.sandbox_type);

        let status = if report.is_available {
            "✅ AVAILABLE"
        } else {
            "❌ NOT AVAILABLE"
        };
        println!("Status:  {}", status);
        if let Some(note) = &report.availability_note {
            println!("Note:    {}", note);
        }

        if report.sandbox_type == default.selected_sandbox_type {
            println!("Default: ✅ This is the backend Guard::default_sandbox() will use");
        }

        match &report.health {
            HealthStatus::Pass => {
                println!("Health:  ✅ PASS (Verified by execution check)");
            }
            HealthStatus::Fail { error } => {
                println!("Health:  ❌ FAIL (Error: {})", error);
            }
            HealthStatus::Skipped => {
                println!("Health:  ➖ SKIPPED");
            }
        }

        if !report.runtime_checks.is_empty() {
            println!("  Runtime checks:");
            for check in &report.runtime_checks {
                let badge = match check.status {
                    RuntimeCheckStatus::Pass => "✅",
                    RuntimeCheckStatus::Fail => "❌",
                    RuntimeCheckStatus::Skipped => "➖",
                };
                println!("    - {} {}: {}", badge, check.name, check.detail);
            }
        }

        println!("\nSupported UCM Capabilities:");
        println!(
            "  - FS Workspace Write: {}",
            if report.capabilities.filesystem_write_workspace {
                "✅ Yes"
            } else {
                "❌ No"
            }
        );
        println!(
            "  - FS Global Write:    {}",
            if report.capabilities.filesystem_write_global {
                "⚠️ Allowed (no OS-level restriction)"
            } else {
                "✅ Blocked by sandbox"
            }
        );
        println!(
            "  - Network Outbound:   {}",
            if report.capabilities.network_outbound_any {
                "⚠️ Allowed (no OS-level restriction)"
            } else {
                "✅ Blocked by sandbox"
            }
        );
        println!(
            "  - Child Process:      {}",
            if report.capabilities.child_process_spawn {
                "✅ Supported"
            } else {
                "❌ Blocked"
            }
        );
        println!();
    }

    println!("====================================================");
    println!("Note: See docs/capability-parity.md for the full platform matrix.");
}
