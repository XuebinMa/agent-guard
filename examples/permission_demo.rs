use agent_guard::{EnforcementResult, PermissionEnforcer, PermissionMode, PermissionPolicy, RuntimePermissionRuleConfig};

fn main() {
    println!("=== Agent Guard - Permission Demo ===\n");

    // 场景1: ReadOnly 模式
    println!("--- Mode: ReadOnly ---");
    let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
        .with_tool_requirement("read_file", PermissionMode::ReadOnly)
        .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
    let enforcer = PermissionEnforcer::new(policy);
    
    print_result("read_file", enforcer.check("read_file", "{}"));
    print_result("write_file", enforcer.check("write_file", "{}"));
    print_result("bash rm -rf", enforcer.check_bash("rm -rf /tmp"));
    print_result("bash cat file", enforcer.check_bash("cat README.md"));
    print_result("file write in workspace", enforcer.check_file_write("/workspace/src/main.rs", "/workspace"));

    println!("\n--- Mode: WorkspaceWrite ---");
    let enforcer2 = PermissionEnforcer::new(PermissionPolicy::new(PermissionMode::WorkspaceWrite));
    print_result("write in workspace", enforcer2.check_file_write("/workspace/src/main.rs", "/workspace"));
    print_result("write outside workspace", enforcer2.check_file_write("/etc/passwd", "/workspace"));

    println!("\n--- Mode: DangerFullAccess ---");
    let enforcer3 = PermissionEnforcer::new(PermissionPolicy::new(PermissionMode::DangerFullAccess));
    print_result("bash rm -rf /tmp/scratch", enforcer3.check_bash("rm -rf /tmp/scratch"));
    print_result("write /etc/passwd", enforcer3.check_file_write("/etc/passwd", "/workspace"));

    println!("\n--- Rule-based: allow git, deny rm -rf ---");
    let rules = RuntimePermissionRuleConfig::new(
        vec!["bash(git:*)".to_string()],
        vec!["bash(rm -rf:*)".to_string()],
        vec![],
    );
    let policy_with_rules = PermissionPolicy::new(PermissionMode::ReadOnly)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
        .with_permission_rules(&rules);
    let enforcer4 = PermissionEnforcer::new(policy_with_rules);
    print_result(r#"bash {"command":"git status"}"#, enforcer4.check("bash", r#"{"command":"git status"}"#));
    print_result(r#"bash {"command":"rm -rf /tmp/x"}"#, enforcer4.check("bash", r#"{"command":"rm -rf /tmp/x"}"#));
}

fn print_result(label: &str, result: EnforcementResult) {
    match result {
        EnforcementResult::Allowed => println!("  [ALLOW] {label}"),
        EnforcementResult::Denied { reason, .. } => println!("  [DENY]  {label}\n         reason: {reason}"),
    }
}
