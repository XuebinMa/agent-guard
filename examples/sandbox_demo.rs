use agent_guard::{FilesystemIsolationMode, SandboxConfig, TrustConfig, TrustPolicy, TrustResolver};

fn main() {
    println!("=== Agent Guard - Sandbox & Trust Demo ===\n");

    println!("--- Sandbox Configuration ---");
    let config = SandboxConfig {
        enabled: Some(true),
        namespace_restrictions: Some(true),
        network_isolation: Some(false),
        filesystem_mode: Some(FilesystemIsolationMode::WorkspaceOnly),
        allowed_mounts: vec!["/tmp".to_string()],
    };
    println!("  Sandbox enabled: {:?}", config.enabled);
    println!("  Namespace restrictions: {:?}", config.namespace_restrictions);
    println!("  Network isolation: {:?}", config.network_isolation);
    println!("  Filesystem mode: {}", config.filesystem_mode.as_ref().map(|m| m.as_str()).unwrap_or("default"));
    println!("  Allowed mounts: {:?}", config.allowed_mounts);

    println!("\n--- Isolation Modes ---");
    for mode in [FilesystemIsolationMode::Off, FilesystemIsolationMode::WorkspaceOnly, FilesystemIsolationMode::AllowList] {
        println!("  {:?} => \"{}\"", mode, mode.as_str());
    }

    println!("\n--- Trust Resolver ---");
    let trust_config = TrustConfig::new()
        .with_allowlisted("/Users/dev/projects")
        .with_allowlisted("/workspace")
        .with_denied("/etc")
        .with_denied("/usr");

    let resolver = TrustResolver::new(trust_config);

    let paths = vec![
        "/Users/dev/projects/my-app",
        "/workspace/agent",
        "/etc/nginx",
        "/home/user/unknown-project",
    ];

    for path in &paths {
        let decision = resolver.resolve(path);
        let policy_str = match decision.policy() {
            Some(TrustPolicy::AutoTrust) => "AutoTrust ✅",
            Some(TrustPolicy::RequireApproval) => "RequireApproval ⚠️",
            Some(TrustPolicy::Deny) => "Deny ❌",
            None => "NotRequired",
        };
        println!("  {path:40} => {policy_str}");
    }

    println!("\n--- Trust Prompt Detection ---");
    let prompts = vec![
        "Do you trust the files in this folder?",
        "trust this folder and continue",
        "Normal output line",
        "allow and continue",
    ];
    for prompt in &prompts {
        let is_prompt = TrustResolver::is_trust_prompt(prompt);
        println!("  {:45} => is_trust_prompt: {is_prompt}", prompt);
    }
}
