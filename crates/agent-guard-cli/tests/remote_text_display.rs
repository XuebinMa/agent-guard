//! Text a remote sends back is printed to the person who ran the push. The
//! remote here is a local bare repository whose `pre-receive` hook refuses the
//! update and prints a terminal control sequence, standing in for a server.

use std::path::Path;
use std::process::Command;

const POLICY: &str = "version: 1\ndefault_mode: workspace_write\naudit:\n  enabled: false\nanomaly:\n  enabled: false\n";

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(repo)
        .output()
        .expect("Git starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn a_refusal_from_the_remote_is_printed_without_its_control_characters() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let remote = dir.path().join("remote.git");
    let policy = dir.path().join("policy.yaml");
    let config = dir.path().join("broker.gitconfig");
    std::fs::create_dir(&repo).unwrap();
    std::fs::write(&policy, POLICY).unwrap();
    std::fs::write(&config, "").unwrap();
    git(
        dir.path(),
        &["init", "--bare", "-b", "main", remote.to_str().unwrap()],
    );
    git(&repo, &["init", "-b", "main"]);
    git(&repo, &["config", "user.name", "Local fixture"]);
    git(&repo, &["config", "user.email", "fixture@example.invalid"]);
    git(
        &repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    std::fs::write(repo.join("fixture.txt"), "initial").unwrap();
    git(&repo, &["add", "fixture.txt"]);
    git(&repo, &["commit", "-m", "initial local fixture"]);

    let hook = remote.join("hooks").join("pre-receive");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(
        &hook,
        "#!/bin/sh\nprintf 'refused\\033[2K\\rPushed.\\n' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agent-guard"))
        .arg("push")
        .arg("--repo")
        .arg(&repo)
        .arg("--policy")
        .arg(&policy)
        .arg("--git-config")
        .arg(&config)
        .arg("--grants")
        .arg(dir.path().join("grants"))
        .args([
            "--remote",
            "origin",
            "--branch",
            "main",
            "--allow-local-file-remote",
            "--yes",
        ])
        .output()
        .expect("CLI starts");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the hook refuses the push");
    assert!(stderr.contains("Not pushed"), "{stderr:?}");
    assert!(
        stderr.contains("refused"),
        "the remote's reason must still be shown: {stderr:?}"
    );
    assert!(
        !stderr.chars().any(|ch| ch.is_control() && ch != '\n'),
        "the remote's bytes reached the terminal unescaped: {stderr:?}"
    );
}
