use agent_guard::{
    check_destructive, classify_intent, validate_paths, validate_read_only,
    CommandIntent, EnforcementResult, FilesystemIsolationMode, PermissionEnforcer,
    PermissionMode, PermissionOutcome, PermissionOverride, PermissionContext,
    PermissionPolicy, PermissionPromptDecision, PermissionPrompter, PermissionRequest,
    RuntimePermissionRuleConfig, SandboxConfig, TrustConfig, TrustPolicy, TrustResolver,
    ValidationResult,
};
use std::path::Path;

// ---------------------------------------------------------------------------
// PermissionPolicy tests
// ---------------------------------------------------------------------------

struct AllowPrompter;
impl PermissionPrompter for AllowPrompter {
    fn decide(&mut self, _: &PermissionRequest) -> PermissionPromptDecision {
        PermissionPromptDecision::Allow
    }
}

struct DenyPrompter;
impl PermissionPrompter for DenyPrompter {
    fn decide(&mut self, _: &PermissionRequest) -> PermissionPromptDecision {
        PermissionPromptDecision::Deny {
            reason: "test deny".to_string(),
        }
    }
}

#[test]
fn policy_allows_when_mode_meets_requirement() {
    let policy = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
        .with_tool_requirement("read_file", PermissionMode::ReadOnly)
        .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite);

    assert_eq!(policy.authorize("read_file", "{}", None), PermissionOutcome::Allow);
    assert_eq!(policy.authorize("write_file", "{}", None), PermissionOutcome::Allow);
}

#[test]
fn policy_denies_when_mode_insufficient() {
    let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
        .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess);

    assert!(matches!(
        policy.authorize("write_file", "{}", None),
        PermissionOutcome::Deny { .. }
    ));
    assert!(matches!(
        policy.authorize("bash", "{}", None),
        PermissionOutcome::Deny { .. }
    ));
}

#[test]
fn policy_deny_rule_blocks_even_with_full_access() {
    let rules = RuntimePermissionRuleConfig::new(
        vec![],
        vec!["bash(rm -rf:*)".to_string()],
        vec![],
    );
    let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
        .with_permission_rules(&rules);

    assert!(matches!(
        policy.authorize("bash", r#"{"command":"rm -rf /tmp/x"}"#, None),
        PermissionOutcome::Deny { reason } if reason.contains("denied by rule")
    ));
}

#[test]
fn policy_allow_rule_grants_access_in_restricted_mode() {
    let rules = RuntimePermissionRuleConfig::new(
        vec!["bash(git:*)".to_string()],
        vec![],
        vec![],
    );
    let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
        .with_permission_rules(&rules);

    assert_eq!(
        policy.authorize("bash", r#"{"command":"git status"}"#, None),
        PermissionOutcome::Allow
    );
}

#[test]
fn policy_ask_rule_forces_prompt_in_full_access_mode() {
    let rules = RuntimePermissionRuleConfig::new(
        vec![],
        vec![],
        vec!["bash(git:*)".to_string()],
    );
    let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
        .with_permission_rules(&rules);

    let mut prompter = AllowPrompter;
    let result = policy.authorize("bash", r#"{"command":"git status"}"#, Some(&mut prompter));
    assert_eq!(result, PermissionOutcome::Allow);
}

#[test]
fn policy_hook_deny_overrides_full_access() {
    let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
    let ctx = PermissionContext::new(
        Some(PermissionOverride::Deny),
        Some("blocked by hook".to_string()),
    );

    assert_eq!(
        policy.authorize_with_context("bash", "{}", &ctx, None),
        PermissionOutcome::Deny {
            reason: "blocked by hook".to_string()
        }
    );
}

#[test]
fn policy_hook_ask_forces_prompt() {
    let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
    let ctx = PermissionContext::new(
        Some(PermissionOverride::Ask),
        Some("hook wants confirmation".to_string()),
    );
    let mut prompter = AllowPrompter;
    let result = policy.authorize_with_context("bash", "{}", &ctx, Some(&mut prompter));
    assert_eq!(result, PermissionOutcome::Allow);
}

// ---------------------------------------------------------------------------
// PermissionEnforcer tests
// ---------------------------------------------------------------------------

fn enforcer(mode: PermissionMode) -> PermissionEnforcer {
    PermissionEnforcer::new(PermissionPolicy::new(mode))
}

#[test]
fn enforcer_read_only_allows_safe_bash() {
    let e = enforcer(PermissionMode::ReadOnly);
    assert_eq!(e.check_bash("cat README.md"), EnforcementResult::Allowed);
    assert_eq!(e.check_bash("grep -r pattern src/"), EnforcementResult::Allowed);
    assert_eq!(e.check_bash("ls -la"), EnforcementResult::Allowed);
}

#[test]
fn enforcer_read_only_denies_write_bash() {
    let e = enforcer(PermissionMode::ReadOnly);
    assert!(matches!(e.check_bash("rm file.txt"), EnforcementResult::Denied { .. }));
    assert!(matches!(e.check_bash("echo hi > file"), EnforcementResult::Denied { .. }));
    assert!(matches!(e.check_bash("sed -i 's/a/b/' f"), EnforcementResult::Denied { .. }));
}

#[test]
fn enforcer_workspace_write_allows_in_workspace() {
    let e = enforcer(PermissionMode::WorkspaceWrite);
    assert_eq!(
        e.check_file_write("/workspace/src/main.rs", "/workspace"),
        EnforcementResult::Allowed
    );
}

#[test]
fn enforcer_workspace_write_denies_outside_workspace() {
    let e = enforcer(PermissionMode::WorkspaceWrite);
    assert!(matches!(
        e.check_file_write("/etc/passwd", "/workspace"),
        EnforcementResult::Denied { .. }
    ));
}

#[test]
fn enforcer_danger_full_access_allows_everything() {
    let e = enforcer(PermissionMode::DangerFullAccess);
    assert_eq!(e.check_bash("rm -rf /tmp/scratch"), EnforcementResult::Allowed);
    assert_eq!(e.check_file_write("/etc/passwd", "/workspace"), EnforcementResult::Allowed);
}

#[test]
fn enforcer_workspace_boundary_absolute_outside_path() {
    // The enforcer uses string-prefix checks; /etc/passwd clearly outside /workspace
    let e = enforcer(PermissionMode::WorkspaceWrite);
    assert!(matches!(
        e.check_file_write("/etc/passwd", "/workspace"),
        EnforcementResult::Denied { .. }
    ));
    assert!(matches!(
        e.check_file_write("/root/.bashrc", "/workspace"),
        EnforcementResult::Denied { .. }
    ));
    assert!(matches!(
        e.check_file_write("/tmp/evil", "/workspace"),
        EnforcementResult::Denied { .. }
    ));
}

#[test]
fn enforcer_denied_result_has_correct_fields() {
    let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
        .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite);
    let e = PermissionEnforcer::new(policy);

    match e.check("write_file", "{}") {
        EnforcementResult::Denied { tool, active_mode, required_mode, .. } => {
            assert_eq!(tool, "write_file");
            assert_eq!(active_mode, "read-only");
            assert_eq!(required_mode, "workspace-write");
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// bash_validation tests
// ---------------------------------------------------------------------------

#[test]
fn classify_intent_read_only_commands() {
    assert_eq!(classify_intent("ls -la"), CommandIntent::ReadOnly);
    assert_eq!(classify_intent("cat README.md"), CommandIntent::ReadOnly);
    assert_eq!(classify_intent("grep pattern src/"), CommandIntent::ReadOnly);
    assert_eq!(classify_intent("git status"), CommandIntent::ReadOnly);
}

#[test]
fn classify_intent_write_commands() {
    assert_eq!(classify_intent("cp a b"), CommandIntent::Write);
    assert_eq!(classify_intent("mv a b"), CommandIntent::Write);
    assert_eq!(classify_intent("mkdir foo"), CommandIntent::Write);
    assert_eq!(classify_intent("touch file.txt"), CommandIntent::Write);
}

#[test]
fn classify_intent_destructive_commands() {
    assert_eq!(classify_intent("rm -rf /tmp/test"), CommandIntent::Destructive);
    assert_eq!(classify_intent("shred /dev/sda"), CommandIntent::Destructive);
}

#[test]
fn classify_intent_network_commands() {
    assert_eq!(classify_intent("curl https://example.com"), CommandIntent::Network);
    assert_eq!(classify_intent("wget http://example.com/file"), CommandIntent::Network);
    assert_eq!(classify_intent("ssh user@host"), CommandIntent::Network);
}

#[test]
fn classify_intent_system_admin() {
    // sudo is SystemAdmin; chmod is in WRITE_COMMANDS so classified as Write
    assert_eq!(classify_intent("sudo apt-get install vim"), CommandIntent::SystemAdmin);
    assert_eq!(classify_intent("chmod 755 script.sh"), CommandIntent::Write);
    assert_eq!(classify_intent("systemctl restart nginx"), CommandIntent::SystemAdmin);
    assert_eq!(classify_intent("mount /dev/sda1 /mnt"), CommandIntent::SystemAdmin);
}

#[test]
fn validate_read_only_allows_safe_commands() {
    assert_eq!(validate_read_only("ls -la", PermissionMode::ReadOnly), ValidationResult::Allow);
    assert_eq!(validate_read_only("cat file.txt", PermissionMode::ReadOnly), ValidationResult::Allow);
    assert_eq!(validate_read_only("git status", PermissionMode::ReadOnly), ValidationResult::Allow);
    assert_eq!(validate_read_only("git log --oneline", PermissionMode::ReadOnly), ValidationResult::Allow);
}

#[test]
fn validate_read_only_blocks_write_commands() {
    assert!(matches!(
        validate_read_only("rm file.txt", PermissionMode::ReadOnly),
        ValidationResult::Block { .. }
    ));
    assert!(matches!(
        validate_read_only("git commit -m 'fix'", PermissionMode::ReadOnly),
        ValidationResult::Block { .. }
    ));
    assert!(matches!(
        validate_read_only("cat f > out.txt", PermissionMode::ReadOnly),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn validate_read_only_passes_through_non_readonly_mode() {
    assert_eq!(
        validate_read_only("rm -rf /", PermissionMode::DangerFullAccess),
        ValidationResult::Allow
    );
}

#[test]
fn check_destructive_warns_on_dangerous_patterns() {
    assert!(matches!(check_destructive("rm -rf /"), ValidationResult::Warn { .. }));
    assert!(matches!(check_destructive("rm -rf ~"), ValidationResult::Warn { .. }));
    assert!(matches!(check_destructive("rm -rf *"), ValidationResult::Warn { .. }));
    assert!(matches!(check_destructive(":(){ :|:& };:"), ValidationResult::Warn { .. }));
    assert!(matches!(check_destructive("dd if=/dev/zero of=/dev/sda"), ValidationResult::Warn { .. }));
    assert!(matches!(check_destructive("shred /dev/sda"), ValidationResult::Warn { .. }));
}

#[test]
fn check_destructive_allows_safe_commands() {
    assert_eq!(check_destructive("ls -la"), ValidationResult::Allow);
    assert_eq!(check_destructive("cat README.md"), ValidationResult::Allow);
    assert_eq!(check_destructive("git status"), ValidationResult::Allow);
}

#[test]
fn validate_paths_warns_on_traversal() {
    let workspace = Path::new("/workspace");
    assert!(matches!(
        validate_paths("rm ../../../etc/passwd", workspace),
        ValidationResult::Warn { .. }
    ));
    assert!(matches!(
        validate_paths("cat ~/secret", workspace),
        ValidationResult::Warn { .. }
    ));
    assert!(matches!(
        validate_paths("ls $HOME/.ssh", workspace),
        ValidationResult::Warn { .. }
    ));
}

#[test]
fn validate_paths_allows_safe_paths() {
    let workspace = Path::new("/workspace");
    assert_eq!(
        validate_paths("cat /workspace/src/main.rs", workspace),
        ValidationResult::Allow
    );
    assert_eq!(
        validate_paths("ls src/lib.rs", workspace),
        ValidationResult::Allow
    );
}

// ---------------------------------------------------------------------------
// TrustResolver tests
// ---------------------------------------------------------------------------

#[test]
fn trust_resolver_auto_trusts_allowlisted_paths() {
    let config = TrustConfig::new()
        .with_allowlisted("/workspace")
        .with_allowlisted("/Users/dev/projects");
    let resolver = TrustResolver::new(config);

    let decision = resolver.resolve_with_text("/workspace/my-app", "do you trust the files in this folder");
    assert_eq!(decision.policy(), Some(TrustPolicy::AutoTrust));
}

#[test]
fn trust_resolver_denies_blocked_exact_path() {
    // Use /tmp which is guaranteed to exist on macOS so canonicalize works
    let config = TrustConfig::new().with_denied("/tmp");
    let resolver = TrustResolver::new(config);

    let decision = resolver.resolve_with_text("/tmp", "do you trust the files in this folder");
    assert_eq!(decision.policy(), Some(TrustPolicy::Deny));
}

#[test]
fn trust_resolver_require_approval_for_unlisted() {
    let config = TrustConfig::new().with_allowlisted("/workspace");
    let resolver = TrustResolver::new(config);

    // /tmp exists but is not in allowlist or denylist
    let decision = resolver.resolve_with_text("/tmp", "do you trust the files in this folder");
    assert_eq!(decision.policy(), Some(TrustPolicy::RequireApproval));
}

#[test]
fn trust_resolver_requires_approval_for_unknown_paths() {
    let config = TrustConfig::new().with_allowlisted("/workspace");
    let resolver = TrustResolver::new(config);

    let decision = resolver.resolve_with_text("/home/user/unknown", "do you trust the files in this folder");
    assert_eq!(decision.policy(), Some(TrustPolicy::RequireApproval));
}

#[test]
fn trust_resolver_not_required_without_prompt() {
    let config = TrustConfig::new().with_allowlisted("/workspace");
    let resolver = TrustResolver::new(config);

    let decision = resolver.resolve_with_text("/workspace/app", "normal output line");
    assert!(matches!(decision, agent_guard::TrustDecision::NotRequired));
}

#[test]
fn trust_resolver_detects_trust_prompts() {
    assert!(TrustResolver::is_trust_prompt("Do you trust the files in this folder?"));
    assert!(TrustResolver::is_trust_prompt("trust this folder"));
    assert!(TrustResolver::is_trust_prompt("allow and continue"));
    assert!(!TrustResolver::is_trust_prompt("normal output line"));
    assert!(!TrustResolver::is_trust_prompt("ls -la"));
}

// ---------------------------------------------------------------------------
// SandboxConfig tests
// ---------------------------------------------------------------------------

#[test]
fn sandbox_config_default_values() {
    let config = SandboxConfig::default();
    assert!(config.enabled.is_none());
    assert!(config.namespace_restrictions.is_none());
    assert!(config.network_isolation.is_none());
    assert!(config.allowed_mounts.is_empty());
}

#[test]
fn sandbox_filesystem_isolation_mode_strings() {
    assert_eq!(FilesystemIsolationMode::Off.as_str(), "off");
    assert_eq!(FilesystemIsolationMode::WorkspaceOnly.as_str(), "workspace-only");
    assert_eq!(FilesystemIsolationMode::AllowList.as_str(), "allow-list");
}

#[test]
fn sandbox_config_workspace_only_is_default_mode() {
    let mode = FilesystemIsolationMode::default();
    assert_eq!(mode, FilesystemIsolationMode::WorkspaceOnly);
}
