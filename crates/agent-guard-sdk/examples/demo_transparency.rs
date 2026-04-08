use agent_guard_sdk::CapabilityDoctor;

fn main() {
    println!("🛡️ agent-guard Demo 3: Platform Transparency (UCM Parity)");
    println!("====================================================\n");

    println!("The Unified Capability Model (UCM) ensures that security policies");
    println!("are platform-agnostic, while mapping them to optimal OS enforcers.\n");

    println!("👉 Action: Running CapabilityDoctor to inspect current host\n");
    
    let reports = CapabilityDoctor::report();
    
    for report in reports {
        println!("--------------------------------------------------");
        println!("Sandbox: {} ({})", report.name, report.sandbox_type);
        
        let status = if report.is_available { "✅ AVAILABLE" } else { "❌ NOT AVAILABLE" };
        println!("Status:  {}", status);
        
        match &report.health {
            agent_guard_sdk::HealthStatus::Pass => {
                println!("Health:  ✅ PASS (Verified by execution check)");
            }
            agent_guard_sdk::HealthStatus::Fail { error } => {
                println!("Health:  ❌ FAIL (Error: {})", error);
            }
            agent_guard_sdk::HealthStatus::Skipped => {
                println!("Health:  ➖ SKIPPED");
            }
        }
        
        println!("\nSupported UCM Capabilities:");
        println!("  - FS Workspace Write: {}", if report.capabilities.filesystem_write_workspace { "✅ Yes" } else { "❌ No" });
        println!("  - FS Global Write:    {}", if report.capabilities.filesystem_write_global { "✅ Restricted" } else { "❌ Unrestricted" });
        println!("  - Network Outbound:   {}", if report.capabilities.network_outbound_any { "❌ Allowed" } else { "✅ Blocked" });
        println!("  - Child Process:      {}", if report.capabilities.child_process_spawn { "✅ Supported" } else { "❌ Blocked" });
        println!();
    }

    println!("====================================================");
    println!("Note: See docs/capability-parity.md for the full platform matrix.");
}
