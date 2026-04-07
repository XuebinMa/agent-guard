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
        println!("  - Syscall Filtering:  {}", if report.capabilities.syscall_filtering { "Yes" } else { "No" });
        println!("  - FS Isolation:       {}", if report.capabilities.filesystem_isolation { "Yes" } else { "No" });
        println!("  - Network Blocking:   {}", if report.capabilities.network_blocking { "Yes" } else { "No" });
        println!("  - Resource Limits:    {}", if report.capabilities.resource_limits { "Yes" } else { "No" });
        println!("  - Process Tree Clean: {}", if report.capabilities.process_tree_cleanup { "Yes" } else { "No" });
        println!();
    }
}
