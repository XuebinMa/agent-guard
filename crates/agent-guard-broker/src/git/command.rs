use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Output};

use super::GitError;

pub(super) fn failed(args: &[&str], output: Output) -> GitError {
    GitError::Failed {
        command: args.join(" "),
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    }
}

pub(super) fn sanitized_git_command(trusted_config: &Path) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    for key in [
        "PATH",
        "PATHEXT",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SSH_AUTH_SOCK",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for (key, value) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("LC_") {
            command.env(key, value);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", trusted_config)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    // Scoped HTTP headers apply to the initial URL but Git may forward them
    // while following a redirect. Never contact a destination other than the
    // one the transaction resolved. Trusted-config validation also rejects
    // URL-scoped overrides, whose specificity could defeat this generic key.
    command.args([
        "-c",
        "http.followRedirects=false",
        "-c",
        "credential.useHttpPath=true",
    ]);
    command
}

fn config_only_command() -> Command {
    let null_config = if cfg!(windows) { "NUL" } else { "/dev/null" };
    sanitized_git_command(Path::new(null_config))
}

pub(super) fn config_values(config: &Path, key: &str) -> Result<Vec<String>, GitError> {
    let args: Vec<OsString> = vec![
        "config".into(),
        "--file".into(),
        config.as_os_str().to_owned(),
        "--no-includes".into(),
        "--null".into(),
        "--get-all".into(),
        key.into(),
    ];
    let output = config_only_command().args(&args).output()?;
    if output.status.success() {
        return nul_fields(&output.stdout, &format!("config --get-all {key}"));
    }
    if output.status.code() == Some(1) {
        return Ok(Vec::new());
    }
    Err(GitError::Failed {
        command: format!("config --file {} --get-all {key}", config.display()),
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

pub(super) fn config_names(config: &Path) -> Result<Vec<String>, GitError> {
    let output = config_only_command()
        .args(["config", "--file"])
        .arg(config)
        .args(["--no-includes", "--name-only", "--list", "--null"])
        .output()?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command: format!("config --file {} --list", config.display()),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    nul_fields(&output.stdout, "config --name-only --list")
}

fn nul_fields(output: &[u8], command: &str) -> Result<Vec<String>, GitError> {
    if output.is_empty() {
        return Ok(Vec::new());
    }
    let decoded = std::str::from_utf8(output).map_err(|error| GitError::Unexpected {
        command: command.to_string(),
        detail: format!("Git emitted non-UTF-8 config data: {error}"),
    })?;
    let mut fields = decoded
        .split('\0')
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if output.last() == Some(&0) {
        fields.pop();
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn public_canary_credential(config: &Path, url: &str) -> Output {
        let mut child = sanitized_git_command(config)
            .args(["credential", "fill"])
            .current_dir(config.parent().expect("config directory"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("local credential context check");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(format!("url={url}\n\n").as_bytes())
            .expect("context");
        child.wait_with_output().expect("credential result")
    }

    /// No network or real credential store: this helper returns only a fixed,
    /// public fixture value. It independently exercises Git's context routing.
    #[test]
    fn git_scopes_public_canary_helpers_and_preserves_the_repository_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("trusted.gitconfig");
        let helper = "!printf 'username=public-fixture\\npassword=public-canary\\n'";
        std::fs::write(&config, format!("[credential]\nhelper = {helper}\n")).expect("config");
        let unbounded = public_canary_credential(&config, "https://unapproved.invalid/other.git");
        assert!(
            unbounded.status.success(),
            "Git invokes an unscoped helper for an arbitrary context"
        );
        assert!(String::from_utf8_lossy(&unbounded.stdout).contains("password=public-canary"));

        std::fs::write(
            &config,
            format!(
                "[credential \"https://approved.invalid:8443/Team/repo.git\"]\nhelper = {helper}\n"
            ),
        )
        .expect("config");
        for url in [
            "https://unapproved.invalid:8443/Team/repo.git",
            "https://approved.invalid/Team/repo.git",
            "https://approved.invalid:8443/Team/repo.git-sibling",
            "https://approved.invalid:8443/team/repo.git",
        ] {
            let output = public_canary_credential(&config, url);
            assert!(
                !output.status.success(),
                "an unmatched context cannot get the fixture credential: {url}"
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("public-canary"));
        }
        let scoped =
            public_canary_credential(&config, "https://approved.invalid:8443/Team/repo.git");
        assert!(
            scoped.status.success(),
            "{}",
            String::from_utf8_lossy(&scoped.stderr)
        );
        assert!(String::from_utf8_lossy(&scoped.stdout).contains("password=public-canary"));
        assert!(
            String::from_utf8_lossy(&scoped.stdout).contains("path=Team/repo.git"),
            "helper context must retain the path"
        );
        std::fs::write(&config, format!("[credential \"https://approved.invalid:8443/Team/repo.git/\"]\nhelper = {helper}\n")).expect("trailing scope");
        assert!(
            public_canary_credential(&config, "https://approved.invalid:8443/Team/repo.git")
                .status
                .success(),
            "Git's single trailing scope slash is implicit"
        );
    }

    struct LoopbackEndpoint {
        address: SocketAddr,
        requests: mpsc::Receiver<String>,
        stop: mpsc::Sender<()>,
        thread: thread::JoinHandle<()>,
    }

    fn loopback_endpoint(response: String) -> LoopbackEndpoint {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let (requests_tx, requests) = mpsc::channel();
        let (stop, stop_rx) = mpsc::channel();
        let thread = thread::spawn(move || loop {
            if stop_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                        let read = stream.read(&mut buffer).expect("read request");
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..read]);
                    }
                    requests_tx
                        .send(String::from_utf8_lossy(&request).into_owned())
                        .unwrap();
                    stream
                        .write_all(response.as_bytes())
                        .expect("write response");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("loopback accept: {error}"),
            }
        });
        LoopbackEndpoint {
            address,
            requests,
            stop,
            thread,
        }
    }

    #[test]
    fn every_sanitized_git_command_disables_http_redirects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("trusted.gitconfig");
        for body in ["", "[http]\n\tfollowRedirects = true\n"] {
            std::fs::write(&config, body).expect("write");
            let output = sanitized_git_command(&config)
                .args(["config", "--get", "http.followRedirects"])
                .current_dir(dir.path())
                .output()
                .expect("git config");
            assert!(output.status.success(), "redirect setting must be explicit");
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "false");
        }
    }

    /// Exercise Git's actual redirect handling with a public dummy header.
    /// HTTP is enabled only on this private test command to avoid a TLS test
    /// dependency; the public broker still permits HTTPS/SSH, not HTTP.
    #[test]
    fn sanitized_git_does_not_forward_a_scoped_header_to_a_redirect_target() {
        let target = loopback_endpoint(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
        );
        let source = loopback_endpoint(format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{}/redirected.git\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            target.address
        ));
        let url = format!("http://{}/repo.git", source.address);
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("trusted.gitconfig");
        std::fs::write(
            &config,
            format!(
                "[http \"http://{}/\"]\n\textraHeader = X-Agent-Guard-Canary: public-test-value\n",
                source.address
            ),
        )
        .expect("write scoped dummy header");
        assert!(
            crate::git::validate::validate_trusted_config_snapshot(&config).is_err(),
            "the private HTTP fixture is not a production authentication scope"
        );

        let output = sanitized_git_command(&config)
            .args([
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.http.allow=always",
                "ls-remote",
                "--",
                &url,
            ])
            .current_dir(dir.path())
            .output()
            .expect("git ls-remote");
        let _ = source.stop.send(());
        let _ = target.stop.send(());
        source.thread.join().expect("source joins");
        target.thread.join().expect("target joins");

        assert!(!output.status.success(), "a redirect must fail closed");
        let request = source
            .requests
            .try_recv()
            .expect("initial request was sent");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-agent-guard-canary: public-test-value"),
            "the fixture must exercise a URL-scoped header: {request}"
        );
        assert!(
            target.requests.try_recv().is_err(),
            "the redirect target must not receive any request or header"
        );
    }
}
