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
            // 7. `cmd <input` — no whitespace. `shell_split` keeps `<input`
            //    as a single token, so no read target is collected. This
            //    mirrors the existing write-side behaviour for `cmd >file`
            //    and is documented as a known limitation.
            (
                "no_space_redirect_not_validated",
                "cat </etc/shadow",
                PermissionMode::WorkspaceWrite,
                ws,
                Expected::Allow,
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
