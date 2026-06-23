use super::tokenize::shell_split;
use super::{
    validate_bash_command, validate_paths, validate_read_only, PermissionMode, ValidationResult,
};
use std::path::Path;

#[test]
fn shell_split_keeps_boolean_operators_together() {
    let parts = shell_split("echo one && echo two || echo three");
    assert_eq!(
        parts,
        vec!["echo", "one", "&&", "echo", "two", "||", "echo", "three"]
    );
}

#[test]
fn shell_split_respects_quotes_around_operators() {
    let parts = shell_split(r#"echo "a && b" && echo 'c || d'"#);
    assert_eq!(parts, vec!["echo", "a && b", "&&", "echo", "c || d"]);
}

#[test]
fn read_only_allows_input_redirection() {
    let result = validate_read_only("cat < input.txt", PermissionMode::ReadOnly);
    assert_eq!(result, ValidationResult::Allow);
}

#[test]
fn validate_paths_allows_workspace_relative_write() {
    let result = validate_paths(
        "echo ok > output.txt",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert_eq!(result, ValidationResult::Allow);
}

#[test]
fn validate_paths_blocks_absolute_path_outside_workspace() {
    let result = validate_paths(
        "echo ok > /etc/passwd",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

#[test]
fn validate_paths_blocks_noclobber_override_redirect_outside_workspace() {
    // `>|` forces a write even under `set -o noclobber`. Before `>|` was
    // tokenized as a single redirection operator it split into `>` then `|`,
    // so the path landed in a fresh pipeline segment with no write target and
    // escaped confinement. Regression for the workspace-escape bypass.
    let result = validate_paths(
        "echo pwned >| /etc/cron.d/x",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

#[test]
fn validate_paths_blocks_glued_noclobber_override_redirect() {
    // Glued form `>|path` with no surrounding spaces must also be caught.
    let result = validate_paths(
        "echo pwned >|/etc/passwd",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

#[test]
fn validate_paths_blocks_parent_dir_escape() {
    let result = validate_paths(
        "echo ok > ../outside.txt",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

#[test]
fn validate_paths_blocks_common_write_command_outside_workspace() {
    let result = validate_paths(
        "tee /etc/passwd",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

#[test]
fn validate_paths_escape_list_allows_listed_absolute_write() {
    // Absolute path outside workspace, but matches an escape glob → allow.
    let escape = vec!["/tmp/**".to_string()];
    let result = validate_paths(
        "echo ok > /tmp/scratch.md",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &escape,
    );
    assert_eq!(result, ValidationResult::Allow);
}

#[test]
fn validate_paths_escape_list_does_not_allow_relative_parent_escape() {
    // Even with an escape glob that would syntactically match the resolved
    // form, a relative `../` write is still rejected — the relative-escape
    // path is a different threat class.
    let escape = vec!["/**".to_string()];
    let result = validate_paths(
        "echo ok > ../outside.txt",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &escape,
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

#[test]
fn validate_paths_escape_list_allows_listed_absolute_read() {
    // Read target symmetry: escape list also lets cat /tmp/... through.
    let escape = vec!["/tmp/**".to_string()];
    let result = validate_paths(
        "cat /tmp/scratch.md",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &escape,
    );
    assert_eq!(result, ValidationResult::Allow);
}

#[test]
fn validate_paths_escape_list_still_blocks_unlisted_absolute() {
    // Path outside workspace and outside the escape list → still blocked.
    let escape = vec!["/tmp/**".to_string()];
    let result = validate_paths(
        "echo ok > /etc/passwd",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &escape,
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

// ── heredoc body literalness (quoting-aware shell_split) ────────────────

#[test]
fn shell_split_masks_quoted_heredoc_body() {
    // Tokens inside a `<<'EOF'` body are literal text, not shell syntax.
    // After masking, the body collapses to whitespace and the `>` /
    // `../escape.txt` from inside the body produce no tokens.
    let parts = shell_split("cat <<'EOF'\necho > ../escape.txt\nEOF\n");
    assert!(
        !parts.iter().any(|t| t == ">"),
        "`>` from heredoc body must not survive tokenization, got {parts:?}"
    );
    assert!(
        !parts.iter().any(|t| t == "../escape.txt"),
        "literal `../escape.txt` from heredoc body must not survive, got {parts:?}"
    );
}

#[test]
fn validate_paths_allows_parent_escape_inside_quoted_heredoc_body() {
    // The exact dogfood bug from 2026-05-20: a commit message body that
    // happens to contain `> ../foo` was being parsed as a real relative
    // parent-dir escape redirect. With masking, the body is invisible to
    // the redirect collector.
    let cmd = "git commit -F - <<'COMMITMSG'\nfix: example\n\nexample text mentions echo > ../escape.txt\nCOMMITMSG\n";
    let result = validate_paths(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert_eq!(result, ValidationResult::Allow);
}

#[test]
fn validate_paths_allows_absolute_write_inside_quoted_heredoc_body() {
    // Same shape, but the body literal is an absolute outside-workspace
    // path. Still must not fire — the shell never opens a file here.
    let cmd = "cat <<'EOF'\ndocs reference: echo > /etc/passwd\nEOF\n";
    let result = validate_paths(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert_eq!(result, ValidationResult::Allow);
}

#[test]
fn validate_paths_blocks_real_redirect_outside_heredoc_body() {
    // Regression: a real `>` redirect outside any heredoc must still
    // block. Combines a real out-of-workspace write with a heredoc whose
    // body contains a fake one — only the real redirect should fire.
    let cmd = "echo ok > /etc/passwd && cat <<'EOF'\nbody mentions echo > /etc/shadow\nEOF\n";
    let result = validate_paths(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    match result {
        ValidationResult::Block { reason } => {
            assert!(
                reason.contains("/etc/passwd"),
                "real redirect to /etc/passwd should be the cited target, got: {reason}"
            );
        }
        other => panic!("expected Block on real redirect, got {other:?}"),
    }
}

#[test]
fn validate_paths_blocks_redirect_outside_unquoted_heredoc_body() {
    // Unquoted-delimiter heredocs are not masked (matches
    // `skip_literal_heredoc_body`'s contract): the substitution scanner
    // still needs to see those bodies. A real `>` outside the heredoc on
    // the same command line must therefore still block.
    let cmd = "echo ok > /etc/passwd <<EOF\nfiller body\nEOF\n";
    let result = validate_paths(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(matches!(result, ValidationResult::Block { .. }));
}

// ── safe-cat-heredoc substitution idiom (dogfood friction polish) ──────

#[test]
fn validate_bash_allows_cat_heredoc_substitution_inside_double_quotes() {
    // The Claude Code system-prompt recommended commit form. Was the top
    // recurring deny on the dogfood JSONL (12 hits, 2026-05-20..27).
    let cmd = "git commit -m \"$(cat <<'EOF'\nfeat: thing\n\nbody\nEOF\n)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert_eq!(result, ValidationResult::Allow, "got {result:?}");
}

#[test]
fn validate_bash_allows_top_level_cat_heredoc_substitution() {
    // Symmetric to the double-quoted case: `$(cat <<'EOF' ... EOF)`
    // with no surrounding quotes is still the same safe shape.
    let cmd = "git commit -m $(cat <<'EOF'\nbody\nEOF\n)";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert_eq!(result, ValidationResult::Allow, "got {result:?}");
}

#[test]
fn validate_bash_allows_cat_heredoc_with_double_quoted_delimiter() {
    // `<<"EOF"` is also a literal-body heredoc; idiom recognition must
    // mirror skip_literal_heredoc_body, which accepts both quote chars.
    let cmd = "git commit -m \"$(cat <<\"EOF\"\nbody\nEOF\n)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert_eq!(result, ValidationResult::Allow, "got {result:?}");
}

#[test]
fn validate_bash_allows_cat_indented_heredoc_substitution() {
    // `<<-` strips leading tabs on the closing delimiter line; the body
    // is still literal, so the same safe-idiom guarantee applies.
    let cmd = "echo \"$(cat <<-'EOF'\n\tbody\n\tEOF\n)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert_eq!(result, ValidationResult::Allow, "got {result:?}");
}

#[test]
fn validate_bash_still_denies_unquoted_heredoc_substitution() {
    // Without quotes on the delimiter the shell expands `$(...)` /
    // backticks inside the body before piping to stdin; the safe-idiom
    // guarantee no longer holds.
    let cmd = "echo \"$(cat <<EOF\nbody\nEOF\n)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(
        matches!(result, ValidationResult::Block { .. }),
        "expected Block, got {result:?}"
    );
}

#[test]
fn validate_bash_still_denies_cat_with_file_argument() {
    // The idiom only allows the heredoc form. A bare `$(cat /etc/passwd)`
    // would let the substitution read an arbitrary file and inject it
    // into the outer command; refuse.
    let cmd = "git commit -m \"$(cat /etc/passwd)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(
        matches!(result, ValidationResult::Block { .. }),
        "expected Block, got {result:?}"
    );
}

#[test]
fn validate_bash_still_denies_substitution_with_chained_command_after_heredoc() {
    // A trailing `; <cmd>` after the heredoc means more shell happens
    // inside `$(...)`. Reject — the safe-idiom guarantee was "exactly
    // `cat` + heredoc + nothing else."
    let cmd = "echo \"$(cat <<'EOF'\nx\nEOF\n; touch /tmp/pwned)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(
        matches!(result, ValidationResult::Block { .. }),
        "expected Block, got {result:?}"
    );
}

#[test]
fn validate_bash_still_denies_non_cat_substitution() {
    // The whitelist is strictly the word "cat"; `printf`, `date`, etc.
    // remain refused so the gate doesn't silently widen.
    let cmd = "echo \"$(date)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(
        matches!(result, ValidationResult::Block { .. }),
        "expected Block, got {result:?}"
    );
}

#[test]
fn validate_bash_still_denies_catx_prefix_match() {
    // Defends the strict word boundary: a command like `catx <<'EOF'`
    // happens to start with the three bytes "cat" but is not the `cat`
    // builtin. Must still fail the idiom check.
    let cmd = "echo \"$(catx <<'EOF'\nx\nEOF\n)\"";
    let result = validate_bash_command(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(
        matches!(result, ValidationResult::Block { .. }),
        "expected Block, got {result:?}"
    );
}

// ── HIGH-1: write-target extraction bypasses (WorkspaceWrite) ───────────
//
// Regression coverage for the audit finding where `validate_paths`
// collected write targets only from the tokens AFTER the command word and
// only for a fixed command allowlist. Three escape classes let an
// out-of-workspace write slip through as `Allow` in WorkspaceWrite mode:
//   1. a redirection placed before the command word (`>/etc/passwd cmd`);
//   2. `dd of=PATH` (`=`-joined operand, not a redirection);
//   3. `tar` creating an archive outside the workspace (`-f`/`--file`).

fn ws_paths(cmd: &str) -> ValidationResult {
    validate_paths(
        cmd,
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    )
}

#[test]
fn blocks_leading_redirect_outside_workspace_glued() {
    // `>/etc/passwd echo x` — redirect is the very first token.
    let result = ws_paths(">/etc/passwd echo pwned");
    match result {
        ValidationResult::Block { reason } => assert!(
            reason.contains("/etc/passwd"),
            "out-of-workspace target should be cited, got: {reason}"
        ),
        other => panic!("expected Block on leading redirect, got {other:?}"),
    }
}

#[test]
fn blocks_leading_redirect_outside_workspace_spaced() {
    // `> /etc/passwd echo x` — redirect leading, separated by a space.
    assert!(matches!(
        ws_paths("> /etc/passwd echo pwned"),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn allows_leading_redirect_inside_workspace() {
    // The fix must not over-block: a leading redirect to a workspace-
    // relative path is still legitimate.
    assert_eq!(ws_paths(">out.txt echo ok"), ValidationResult::Allow);
}

#[test]
fn blocks_dd_of_outside_workspace() {
    // `dd of=/etc/passwd` writes to /etc from stdin; no `if=` means
    // check_destructive's "dd if=" substring never fires either.
    assert!(matches!(
        ws_paths("dd of=/etc/passwd"),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn blocks_dd_of_outside_workspace_in_pipeline() {
    assert!(matches!(
        ws_paths("echo pwned | dd of=/etc/cron.d/x"),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn allows_dd_of_inside_workspace() {
    assert_eq!(
        ws_paths("dd if=/dev/zero of=out.bin"),
        ValidationResult::Allow
    );
}

#[test]
fn blocks_tar_create_outside_workspace() {
    assert!(matches!(
        ws_paths("tar -cf /etc/evil.tar ."),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn blocks_tar_create_dashless_outside_workspace() {
    // Old-style dashless flag bundle: `tar czf /etc/evil.tar .`.
    assert!(matches!(
        ws_paths("tar czf /etc/evil.tar ."),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn blocks_tar_create_long_option_outside_workspace() {
    assert!(matches!(
        ws_paths("tar --create --file=/etc/evil.tar ."),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn allows_tar_create_inside_workspace() {
    // No FP: creating an archive at a workspace-relative path is allowed.
    assert_eq!(ws_paths("tar -cf bundle.tar src"), ValidationResult::Allow);
}

#[test]
fn allows_tar_extract_reading_outside_workspace() {
    // Extraction reads the `-f` archive (output goes to the cwd); the
    // archive path must NOT be treated as a write target, so an absolute
    // source archive does not spuriously block.
    assert_eq!(
        ws_paths("tar -xf /opt/pkg/archive.tar"),
        ValidationResult::Allow
    );
}

#[test]
fn blocks_leading_read_redirect_outside_workspace() {
    // Symmetric `<` fix: `</etc/shadow cat` reads outside the workspace.
    assert!(matches!(
        ws_paths("</etc/shadow cat"),
        ValidationResult::Block { .. }
    ));
}

#[test]
fn end_to_end_validate_bash_blocks_leading_redirect() {
    // Full pipeline (not just validate_paths) must deny.
    let result = validate_bash_command(
        ">/etc/passwd echo pwned",
        PermissionMode::WorkspaceWrite,
        Path::new("/workspace"),
        &[],
    );
    assert!(
        matches!(result, ValidationResult::Block { .. }),
        "got {result:?}"
    );
}
