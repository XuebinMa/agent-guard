//! Issue #161: failures must survive the real fork/exec boundary, not only a
//! resolver helper. Fault selection is private, per call, and test-only.

use super::{execute_with_native_seccomp_options, SetupFault, SetupOptions};
use crate::{SandboxContext, SandboxError};
use agent_guard_core::PolicyMode;

fn context(directory: &std::path::Path) -> SandboxContext {
    SandboxContext {
        mode: PolicyMode::WorkspaceWrite,
        working_directory: directory.to_path_buf(),
        timeout_ms: Some(3_000),
    }
}

fn failure(fault: SetupFault, missing_directory: bool) -> (SandboxError, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("private test directory");
    let marker = directory.path().join("must-not-run");
    let command = format!("printf ran > '{}'", marker.display());
    let mut context = context(directory.path());
    if missing_directory {
        context.working_directory = directory.path().join("missing-directory");
    }
    let error = execute_with_native_seccomp_options(
        &command,
        &context,
        SetupOptions { fault: Some(fault) },
    )
    .expect_err("injected setup failure must block execution");
    assert!(!marker.exists(), "setup failure executed the command");
    (error, directory)
}

#[test]
fn required_name_error_reaches_parent_without_running_command() {
    let (error, _directory) = failure(SetupFault::MissingSyscall, false);
    assert!(
        matches!(&error, SandboxError::FilterSetup(message) if message.contains("required seccomp syscall 'connect'")),
        "required-name diagnostic was lost: {error:?}"
    );
}

#[test]
fn required_name_failure_precedes_spawn_validation() {
    let (error, _directory) = failure(SetupFault::MissingSyscall, true);
    assert!(
        matches!(&error, SandboxError::FilterSetup(message) if message.contains("required seccomp syscall 'connect'")),
        "preflight did not run in the parent before spawn: {error:?}"
    );
}

#[test]
fn invalid_filter_is_setup_error_without_running_command() {
    let (error, _directory) = failure(SetupFault::InvalidFilter, false);
    assert!(
        matches!(&error, SandboxError::FilterSetup(message) if message.contains("install seccomp BPF") && message.contains("22")),
        "kernel installation failure lost its stage or errno: {error:?}"
    );
}

#[test]
fn no_new_privileges_failure_retains_setup_stage() {
    let (error, _directory) = failure(SetupFault::NoNewPrivileges, false);
    assert!(
        matches!(&error, SandboxError::FilterSetup(message) if message.contains("no_new_privs") && message.contains("22")),
        "no_new_privs failure lost its stage or errno: {error:?}"
    );
}

#[test]
fn ordinary_spawn_failure_is_not_filter_setup() {
    let directory = tempfile::tempdir().expect("private test directory");
    let error = execute_with_native_seccomp_options(
        "echo must-not-run",
        &context(&directory.path().join("missing-directory")),
        SetupOptions::default(),
    )
    .expect_err("missing working directory must fail");
    assert!(
        matches!(error, SandboxError::ExecutionFailed(_)),
        "{error:?}"
    );
}

#[test]
fn full_access_does_not_prepare_or_install_a_filter() {
    let directory = tempfile::tempdir().expect("private test directory");
    let mut context = context(directory.path());
    context.mode = PolicyMode::FullAccess;
    let output = execute_with_native_seccomp_options(
        "echo full-access",
        &context,
        SetupOptions {
            fault: Some(SetupFault::MissingSyscall),
        },
    )
    .expect("FullAccess must preserve its explicit no-filter contract");
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout.trim(), "full-access");
}
