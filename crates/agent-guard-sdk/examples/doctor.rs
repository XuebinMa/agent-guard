use agent_guard_sdk::{CapabilityDoctor, Guard, HealthStatus, RuntimeCheckStatus};

fn main() {
    println!("🛡️ agent-guard doctor — Host Capability Report\n");

    let default = Guard::default_sandbox_diagnosis();
    println!("Default SDK sandbox:");
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

        match &report.health {
            HealthStatus::Pass => {
                println!("Health:  ✅ PASS");
            }
            HealthStatus::Fail { error } => {
                println!("Health:  ❌ FAIL (Error: {})", error);
            }
            HealthStatus::Skipped => {
                println!("Health:  ➖ SKIPPED");
            }
        }

        if report.sandbox_type == default.selected_sandbox_type {
            println!("Default: ✅ Selected by Guard::default_sandbox()");
        } else if default.fallback_to_noop && report.sandbox_type == "none" {
            println!("Default: ✅ Selected as explicit fallback");
        }

        if !report.runtime_checks.is_empty() {
            println!("Runtime checks:");
            for check in &report.runtime_checks {
                let badge = match check.status {
                    RuntimeCheckStatus::Pass => "✅",
                    RuntimeCheckStatus::Fail => "❌",
                    RuntimeCheckStatus::Skipped => "➖",
                };
                println!("  - {} {}: {}", badge, check.name, check.detail);
            }
        }

        println!("Capabilities:");
        println!(
            "  - FS Workspace Read:  {}",
            if report.capabilities.filesystem_read_workspace {
                "Yes"
            } else {
                "No"
            }
        );
        println!(
            "  - FS Global Read:     {}",
            if report.capabilities.filesystem_read_global {
                "Yes"
            } else {
                "No"
            }
        );
        println!(
            "  - FS Workspace Write: {}",
            if report.capabilities.filesystem_write_workspace {
                "Yes"
            } else {
                "No"
            }
        );
        println!(
            "  - FS Global Write:    {}",
            if report.capabilities.filesystem_write_global {
                "Yes"
            } else {
                "No"
            }
        );
        println!(
            "  - Network Any:        {}",
            if report.capabilities.network_outbound_any {
                "Yes"
            } else {
                "No"
            }
        );
        println!();
    }
}
