#[cfg(test)]
mod bash_read_only_tests {
    use crate::bash::{validate_command, validate_read_only, PermissionMode, ValidationResult};
    use std::path::Path;

    fn ro() -> PermissionMode {
        PermissionMode::ReadOnly
    }
    fn ws() -> PermissionMode {
        PermissionMode::WorkspaceWrite
    }
    fn workspace() -> &'static Path {
        Path::new("/workspace")
    }

    // ── read-only: write commands blocked ────────────────────────────────────

    #[test]
    fn blocks_rm_in_read_only() {
        let r = validate_read_only("rm -rf /tmp", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_cp_in_read_only() {
        let r = validate_read_only("cp src dst", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_mv_in_read_only() {
        let r = validate_read_only("mv a b", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_mkdir_in_read_only() {
        let r = validate_read_only("mkdir /tmp/test", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_touch_in_read_only() {
        let r = validate_read_only("touch file.txt", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_tee_in_read_only() {
        // Regression: tee was incorrectly listed as read-only upstream.
        let r = validate_read_only("tee output.txt", ro());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "tee must be blocked in read-only mode"
        );
    }

    #[test]
    fn blocks_write_redirection_in_read_only() {
        let r = validate_read_only("echo hello > file.txt", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_append_redirection_in_read_only() {
        let r = validate_read_only("echo hello >> file.txt", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_ls_in_read_only() {
        let r = validate_read_only("ls -la", ro());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_cat_in_read_only() {
        let r = validate_read_only("cat Cargo.toml", ro());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_grep_in_read_only() {
        let r = validate_read_only("grep -r pattern src/", ro());
        assert_eq!(r, ValidationResult::Allow);
    }

    // ── git in read-only ─────────────────────────────────────────────────────

    #[test]
    fn allows_git_status_in_read_only() {
        let r = validate_read_only("git status", ro());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_git_log_in_read_only() {
        let r = validate_read_only("git log --oneline -10", ro());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn blocks_git_push_in_read_only() {
        let r = validate_read_only("git push origin main", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_git_commit_in_read_only() {
        let r = validate_read_only("git commit -m 'msg'", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    // ── state-modifying in read-only ─────────────────────────────────────────

    #[test]
    fn blocks_apt_get_in_read_only() {
        let r = validate_read_only("apt-get install vim", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_npm_install_in_read_only() {
        let r = validate_read_only("npm install", ro());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    // ── non-read-only modes always allow ────────────────────────────────────

    #[test]
    fn workspace_write_allows_rm() {
        let r = validate_read_only("rm file.txt", ws());
        assert_eq!(r, ValidationResult::Allow);
    }

    // ── full pipeline ────────────────────────────────────────────────────────

    #[test]
    fn full_pipeline_allows_safe_command() {
        let r = validate_command("cargo build", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn full_pipeline_blocks_write_in_read_only() {
        let r = validate_command("rm file.txt", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }
}

#[cfg(test)]
mod bash_destructive_tests {
    use crate::bash::{check_destructive, ValidationResult};

    #[test]
    fn detects_rm_rf_root() {
        let r = check_destructive("rm -rf /");
        assert!(matches!(r, ValidationResult::Warn { .. }));
    }

    #[test]
    fn detects_rm_rf_home() {
        let r = check_destructive("rm -rf ~");
        assert!(matches!(r, ValidationResult::Warn { .. }));
    }

    #[test]
    fn detects_rm_rf_star() {
        let r = check_destructive("rm -rf *");
        assert!(matches!(r, ValidationResult::Warn { .. }));
    }

    #[test]
    fn detects_mkfs() {
        let r = check_destructive("mkfs.ext4 /dev/sdb");
        assert!(matches!(r, ValidationResult::Warn { .. }));
    }

    #[test]
    fn detects_dd() {
        let r = check_destructive("dd if=/dev/zero of=/dev/sda");
        assert!(matches!(r, ValidationResult::Warn { .. }));
    }

    #[test]
    fn detects_fork_bomb() {
        let r = check_destructive(":(){ :|:& };:");
        assert!(matches!(r, ValidationResult::Warn { .. }));
    }

    #[test]
    fn detects_shred() {
        let r = check_destructive("shred -u secret.txt");
        assert!(matches!(r, ValidationResult::Warn { .. }));
    }

    #[test]
    fn safe_rm_not_warned() {
        let r = check_destructive("rm file.txt");
        // no -r and -f together, no pattern match
        assert_eq!(r, ValidationResult::Allow);
    }
}

#[cfg(test)]
mod bash_sed_tests {
    use crate::bash::{validate_sed, PermissionMode, ValidationResult};

    #[test]
    fn sed_inplace_blocked_in_read_only() {
        let r = validate_sed("sed -i 's/foo/bar/' file.txt", PermissionMode::ReadOnly);
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn sed_without_inplace_allowed_in_read_only() {
        let r = validate_sed("sed 's/foo/bar/' file.txt", PermissionMode::ReadOnly);
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn sed_inplace_allowed_in_workspace_write() {
        let r = validate_sed(
            "sed -i 's/foo/bar/' file.txt",
            PermissionMode::WorkspaceWrite,
        );
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn non_sed_command_always_allowed() {
        let r = validate_sed("awk '{print $1}'", PermissionMode::ReadOnly);
        assert_eq!(r, ValidationResult::Allow);
    }
}

#[cfg(test)]
mod bash_classify_tests {
    use crate::bash::{classify_intent, CommandIntent};

    #[test]
    fn ls_is_read_only() {
        assert_eq!(classify_intent("ls -la"), CommandIntent::ReadOnly);
    }

    #[test]
    fn cat_is_read_only() {
        assert_eq!(classify_intent("cat file.txt"), CommandIntent::ReadOnly);
    }

    #[test]
    fn rm_is_destructive() {
        assert_eq!(classify_intent("rm file.txt"), CommandIntent::Destructive);
    }

    #[test]
    fn cp_is_write() {
        assert_eq!(classify_intent("cp a b"), CommandIntent::Write);
    }

    #[test]
    fn curl_is_network() {
        assert_eq!(
            classify_intent("curl https://example.com"),
            CommandIntent::Network
        );
    }

    #[test]
    fn npm_is_package_management() {
        assert_eq!(
            classify_intent("npm install express"),
            CommandIntent::PackageManagement
        );
    }

    #[test]
    fn sudo_is_system_admin() {
        assert_eq!(
            classify_intent("sudo apt-get update"),
            CommandIntent::SystemAdmin
        );
    }

    #[test]
    fn git_status_is_read_only() {
        assert_eq!(classify_intent("git status"), CommandIntent::ReadOnly);
    }

    #[test]
    fn git_push_is_write() {
        assert_eq!(
            classify_intent("git push origin main"),
            CommandIntent::Write
        );
    }

    #[test]
    fn sed_inplace_is_write() {
        assert_eq!(
            classify_intent("sed -i 's/foo/bar/' file"),
            CommandIntent::Write
        );
    }
}

#[cfg(test)]
mod path_tests {
    use crate::path::{
        detect_trust_prompt, validate_path_access, TrustConfig, TrustDecision, TrustPolicy,
        TrustResolver,
    };

    // ── detect_trust_prompt ──────────────────────────────────────────────────

    #[test]
    fn detects_trust_cue_do_you_trust() {
        assert!(detect_trust_prompt(
            "Do you trust the files in this folder?"
        ));
    }

    #[test]
    fn detects_trust_cue_allow_and_continue() {
        assert!(detect_trust_prompt("Please allow and continue to proceed."));
    }

    #[test]
    fn does_not_detect_unrelated_text() {
        assert!(!detect_trust_prompt("Hello, how can I help you today?"));
    }

    #[test]
    fn case_insensitive_detection() {
        assert!(detect_trust_prompt("TRUST THIS FOLDER"));
    }

    // ── TrustResolver ────────────────────────────────────────────────────────

    #[test]
    fn no_trust_prompt_returns_not_required() {
        let cfg = TrustConfig::new();
        let resolver = TrustResolver::new(cfg);
        let decision = resolver.resolve_with_text("/workspace", "Hello world");
        assert_eq!(decision, TrustDecision::NotRequired);
    }

    #[test]
    fn allowlisted_path_auto_trusts() {
        let cfg = TrustConfig::new().with_allowlisted("/workspace");
        let resolver = TrustResolver::new(cfg);
        let decision =
            resolver.resolve_with_text("/workspace", "do you trust the files in this folder");
        assert_eq!(decision.policy(), Some(TrustPolicy::AutoTrust));
    }

    #[test]
    fn denied_path_returns_deny() {
        let cfg = TrustConfig::new().with_denied("/malicious");
        let resolver = TrustResolver::new(cfg);
        let decision =
            resolver.resolve_with_text("/malicious", "do you trust the files in this folder");
        assert_eq!(decision.policy(), Some(TrustPolicy::Deny));
    }

    #[test]
    fn unknown_path_requires_approval() {
        let cfg = TrustConfig::new();
        let resolver = TrustResolver::new(cfg);
        let decision =
            resolver.resolve_with_text("/unknown", "do you trust the files in this folder");
        assert_eq!(decision.policy(), Some(TrustPolicy::RequireApproval));
    }

    // ── validate_path_access ─────────────────────────────────────────────────

    #[test]
    fn path_inside_trusted_root_is_valid() {
        // Use /tmp which always exists and canonicalizes
        assert!(validate_path_access("/tmp", "/tmp"));
    }

    #[test]
    fn root_path_outside_tmp_is_invalid() {
        assert!(!validate_path_access("/etc/passwd", "/tmp"));
    }
}
