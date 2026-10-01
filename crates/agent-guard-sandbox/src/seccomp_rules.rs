use std::fmt::Display;

use agent_guard_core::PolicyMode;

pub(crate) const NETWORK_DENY_SYSCALLS: &[&str] = &[
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "shutdown",
    "setsockopt",
    "getsockopt",
];

pub(crate) const COMMON_DENY_SYSCALLS: &[&str] = &[
    "ptrace",
    "mount",
    "umount2",
    "swapon",
    "swapoff",
    "reboot",
    "kexec_load",
    "finit_module",
    "init_module",
    "delete_module",
    "bpf",
    "unshare",
    "setns",
    // io_uring submits socket/connect and file-write operations through a
    // shared ring buffer, bypassing the ordinary syscall deny lists.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // Memory injection primitive in the same class as ptrace.
    "process_vm_writev",
];

pub(crate) const READ_ONLY_WRITE_FLAG_DENIES: &[(&str, u32)] = &[("open", 1), ("openat", 2)];

pub(crate) const READ_ONLY_DENY_SYSCALLS: &[&str] = &[
    "openat2",
    "memfd_create",
    "creat",
    "truncate",
    "ftruncate",
    "mkdir",
    "mkdirat",
    "rmdir",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "mknod",
    "mknodat",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
    "lchown",
    "utime",
    "utimensat",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "copy_file_range",
];

pub(crate) fn resolve_required_syscall_with<T, E>(
    name: &str,
    mut resolver: impl FnMut(&str) -> Result<T, E>,
) -> Result<T, String>
where
    E: Display,
{
    resolver(name)
        .map_err(|error| format!("failed to resolve required seccomp syscall '{name}': {error}"))
}

pub(crate) fn preflight_required_syscalls_with<T, E>(
    mode: &PolicyMode,
    mut resolver: impl FnMut(&str) -> Result<T, E>,
) -> Result<(), String>
where
    E: Display,
{
    for name in NETWORK_DENY_SYSCALLS
        .iter()
        .chain(COMMON_DENY_SYSCALLS.iter())
    {
        resolve_required_syscall_with(name, &mut resolver)?;
    }

    if matches!(mode, PolicyMode::ReadOnly) {
        for (name, _) in READ_ONLY_WRITE_FLAG_DENIES {
            resolve_required_syscall_with(name, &mut resolver)?;
        }
        for name in READ_ONLY_DENY_SYSCALLS {
            resolve_required_syscall_with(name, &mut resolver)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{preflight_required_syscalls_with, resolve_required_syscall_with};
    use agent_guard_core::PolicyMode;

    #[test]
    fn required_syscall_resolution_error_is_not_silently_dropped() {
        let error =
            resolve_required_syscall_with::<(), _>("connect", |_| Err("injected resolver failure"))
                .expect_err("a required deny rule must fail closed when it cannot be resolved");

        assert_eq!(
            error,
            "failed to resolve required seccomp syscall 'connect': injected resolver failure"
        );
    }

    #[test]
    fn preflight_propagates_required_resolution_error_for_active_mode() {
        let error =
            preflight_required_syscalls_with::<(), _>(&PolicyMode::WorkspaceWrite, |name| {
                if name == "connect" {
                    Err("injected resolver failure")
                } else {
                    Ok(())
                }
            })
            .expect_err("preflight must reject a degraded required deny list");

        assert_eq!(
            error,
            "failed to resolve required seccomp syscall 'connect': injected resolver failure"
        );
    }

    #[test]
    fn preflight_only_resolves_read_only_rules_in_read_only_mode() {
        preflight_required_syscalls_with::<(), &str>(&PolicyMode::WorkspaceWrite, |name| {
            assert_ne!(name, "openat2", "read-only rule leaked into workspace mode");
            Ok(())
        })
        .expect("workspace-write preflight should exclude read-only rules");

        let error = preflight_required_syscalls_with::<(), _>(&PolicyMode::ReadOnly, |name| {
            if name == "openat2" {
                Err("injected read-only failure")
            } else {
                Ok(())
            }
        })
        .expect_err("read-only preflight must include read-only rules");

        assert!(error.contains("required seccomp syscall 'openat2'"));
    }
}
