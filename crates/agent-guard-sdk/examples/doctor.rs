use agent_guard_sdk::{CapabilityDoctor, HealthStatus};

fn main() {
    println!("🛡️ agent-guard doctor — Host Capability Report\n");
    
    let reports = CapabilityDoctor::report();
    
    for report in reports {
        println!("--------------------------------------------------");
        println!("Sandbox: {} ({})", report.name, report.sandbox_type);
        
        let status = if report.is_available { "✅ AVAILABLE" } else { "❌ NOT AVAILABLE" };
        println!("Status:  {}", status);
        
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
        
        println!("Capabilities:");
        println!("  - FS Workspace Read:  {}", if report.capabilities.filesystem_read_workspace { "Yes" } else { "No" });
        println!("  - FS Global Read:     {}", if report.capabilities.filesystem_read_global { "Yes" } else { "No" });
        println!("  - FS Workspace Write: {}", if report.capabilities.filesystem_write_workspace { "Yes" } else { "No" });
        println!("  - FS Global Write:    {}", if report.capabilities.filesystem_write_global { "Yes" } else { "No" });
        println!("  - Network Any:        {}", if report.capabilities.network_outbound_any { "Yes" } else { "No" });
        println!();
    }
}
