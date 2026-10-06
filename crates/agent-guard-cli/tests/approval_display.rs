//! What `list` and `show` print is what a person approves from. The ledger is
//! a file any same-user process can write, and its message restates text from
//! the agent's command, so nothing read from it may reach the terminal as a
//! control sequence.

use std::process::Command;

use agent_guard_sdk::approval::ApprovalLedger;

const HOSTILE_MESSAGE: &str =
    "Approve git push to evil.invalid\u{1b}[2K\rApprove git push to origin, main\u{202e}";

fn run(ledger: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-guard"))
        .arg("--ledger")
        .arg(ledger)
        .args(args)
        .output()
        .expect("CLI starts");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("UTF-8 output")
}

fn assert_inert(rendered: &str) {
    assert!(
        !rendered
            .chars()
            .any(|ch| (ch.is_control() && ch != '\n') || ch == '\u{202e}'),
        "ledger text reached the terminal unescaped: {rendered:?}"
    );
}

#[test]
fn list_and_show_escape_control_characters_from_the_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("approvals.jsonl");
    ApprovalLedger::open(&path)
        .create_pending(
            "req-1",
            "bash\u{1b}[31m",
            "hash",
            HOSTILE_MESSAGE,
            Some("agent\r\u{1b}[1A".to_string()),
            None,
        )
        .expect("pending request");

    let listed = run(&path, &["list"]);
    assert_inert(&listed);
    assert!(listed.contains("evil.invalid\\u{1b}"), "{listed}");
    assert_eq!(
        listed.lines().count(),
        2,
        "one header and one row: {listed}"
    );

    let shown = run(&path, &["show", "req-1"]);
    assert_inert(&shown);
    assert!(shown.contains("evil.invalid\\u{1b}"), "{shown}");
}

#[test]
fn ordinary_ledger_text_is_printed_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("approvals.jsonl");
    ApprovalLedger::open(&path)
        .create_pending(
            "req-1",
            "bash",
            "hash",
            "Approve git push to origin, 功能/登录",
            Some("claude-code".to_string()),
            None,
        )
        .expect("pending request");

    let shown = run(&path, &["show", "req-1"]);
    assert!(
        shown.contains("message:      Approve git push to origin, 功能/登录"),
        "{shown}"
    );
    assert!(shown.contains("agent_id:     claude-code"), "{shown}");
}
