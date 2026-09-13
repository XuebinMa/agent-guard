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
