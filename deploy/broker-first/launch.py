#!/usr/bin/env python3
"""One native-Linux Docker profile, not a generic privileged command service."""

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit
import uuid


AGENT_USER = "65532:65532"
CONFIG_KEYS = {
    "schema", "host_root", "image", "docker_binary", "broker_binary",
    "agent_command", "destination", "remote", "branch",
}
CONTAINER_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/home/agent", "TMPDIR": "/tmp",
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    # Workspace root is host-owned so the agent cannot replace its recorded
    # identity. Trust only this path for the agent's own Git ownership check.
    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory",
    "GIT_CONFIG_VALUE_0": "/workspace",
}
SCRATCH = {
    "/tmp": "rw,nosuid,nodev,noexec,size=268435456,mode=1777",
    "/home/agent": "rw,nosuid,nodev,noexec,size=67108864,uid=65532,gid=65532,mode=0700",
}
MASKED_PATHS = {
    "/proc/asound", "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
    "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
    "/sys/firmware", "/sys/devices/virtual/powercap",
}
READONLY_PATHS = {"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}


class ProfileError(ValueError):
    """A check failed; never continue with a weaker profile."""


@dataclass(frozen=True)
class Profile:
    host_root: Path
    image: str
    docker_binary: str
    broker_binary: str
    agent_command: tuple
    destination: str
    remote: str
    branch: str

    @property
    def control(self):
        return self.host_root / "control"

    @property
    def workspace(self):
        return self.host_root / "development/workspace"

    @property
    def container_name(self):
        return "agent-guard-" + hashlib.sha256(str(self.host_root).encode()).hexdigest()[:20]


def absolute_path(value, name):
    if (not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9._/-]+", value)
            or any(part in {".", ".."} for part in value.split("/"))):
        raise ProfileError(f"{name} must be a plain absolute path without traversal or mount delimiters")
    return Path(value)


def validate_config(raw):
    if not isinstance(raw, dict) or set(raw) != CONFIG_KEYS:
        raise ProfileError("deployment keys must exactly match the fixed profile; unknown keys are refused")
    if type(raw["schema"]) is not int or raw["schema"] != 1:
        raise ProfileError("unsupported deployment schema")
    root = absolute_path(raw["host_root"], "host_root")
    if len(root.parts) < 3:
        raise ProfileError("host_root must be a dedicated directory, not a filesystem root")
    for field, basename in [("docker_binary", "docker"), ("broker_binary", "agent-guard")]:
        if absolute_path(raw[field], field).name != basename:
            raise ProfileError(f"{field} must name {basename}")
    if not isinstance(raw["image"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", raw["image"]):
        raise ProfileError("image must be an already-installed exact local image ID")
    command = raw["agent_command"]
    if not isinstance(command, list) or not 2 <= len(command) <= 32:
        raise ProfileError("agent_command needs an absolute executable and at least one argument")
    absolute_path(command[0], "agent executable")
    if any(not isinstance(arg, str) or len(arg) > 4096
           or any(ord(char) < 32 or ord(char) == 127 for char in arg) for arg in command):
        raise ProfileError("agent arguments must be bounded strings without control characters")
    for field in ["remote", "branch"]:
        value = raw[field]
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value):
            raise ProfileError(f"{field} must use the broker's safe name character set")
    branch = raw["branch"]
    if (".." in branch or "//" in branch or branch.endswith(("/", "."))
            or any(part.startswith(".") or part.endswith(".lock") for part in branch.split("/"))):
        raise ProfileError("branch is not a supported Git branch")
    destination = raw["destination"]
    if not isinstance(destination, str) or not destination.isascii():
        raise ProfileError("destination must be a canonical ASCII HTTPS URL")
    try:
        parsed = urlsplit(destination)
        host, port = parsed.hostname, parsed.port
    except ValueError as error:
        raise ProfileError("invalid HTTPS destination") from error
    authority = host + (f":{port}" if port is not None else "") if host else ""
    if (parsed.scheme != "https" or parsed.netloc != authority
            or not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", host or "")
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or not parsed.path.startswith("/")
            or parsed.path == "/" or port in {0, 443}
            or not re.fullmatch(r"/[A-Za-z0-9._/-]+", parsed.path)
            or "//" in parsed.path or any(part in {".", ".."} for part in parsed.path.split("/"))):
        raise ProfileError("destination must be canonical HTTPS without userinfo, escapes, or ambiguous spelling")
    return Profile(root, raw["image"], raw["docker_binary"], raw["broker_binary"],
                   tuple(command), destination, raw["remote"], branch)


def read_private_file(path):
    """No symlink following; private, caller-owned, single-link ordinary files."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o077 or metadata.st_nlink != 1):
                raise ProfileError(f"not a private caller-owned ordinary file: {path}")
            content = source.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise ProfileError(f"private file is too large: {path}")
            return content.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise ProfileError(f"cannot safely read private file: {path}") from error


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_config(path):
    try:
        profile = validate_config(json.loads(read_private_file(path), object_pairs_hook=unique_object))
    except json.JSONDecodeError as error:
        raise ProfileError("invalid deployment JSON") from error
    if Path(path).absolute() != profile.control / "deployment.json":
        raise ProfileError("configuration must be at host_root/control/deployment.json")
    return profile


def private_directory(path):
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077):
        raise ProfileError(f"not a private caller-owned directory: {path}")


def trusted_ancestors(path):
    """Protect path replacement too; root-owned sticky temporary roots are allowed."""
    for parent in reversed(path.parents):
        metadata = parent.lstat()
        protected_sticky = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, os.getuid()}
                or (metadata.st_mode & 0o022 and not protected_sticky)):
            raise ProfileError(f"untrusted or replaceable parent directory: {parent}")


def check_private_tree(root):
    private_directory(root)
    pending = [root]
    while pending:
        # scandir errors propagate: unlike glob, an unreadable path is not skipped.
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    private_directory(path)
                    pending.append(path)
                else:
                    read_private_file(path)


def write_new_private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(value, target, sort_keys=True)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())


def initialize_workspace(profile):
    trusted_ancestors(profile.host_root)
    private_directory(profile.host_root)
    private_directory(profile.control)
    for name in ["policy.yaml", "broker.gitconfig"]:
        read_private_file(profile.control / name)
    parent = profile.workspace.parent
    if parent.exists():
        private_directory(parent)
    else:
        parent.mkdir(mode=0o700)
    if profile.workspace.exists() or profile.workspace.is_symlink():
        raise ProfileError("workspace must be newly created; no existing directory or repository import")
    for name in ["home", "grants", "records", "tmp", "docker", "credentials"]:
        directory = profile.control / name
        directory.mkdir(mode=0o700, exist_ok=True)
        private_directory(directory)
    profile.workspace.mkdir(mode=0o1777)
    profile.workspace.chmod(0o1777)
    metadata = profile.workspace.stat()
    write_new_private_json(profile.control / "workspace.json", {
        "schema": 1, "device": metadata.st_dev, "inode": metadata.st_ino,
    })


def check_workspace(profile):
    private_directory(profile.workspace.parent)
    metadata = profile.workspace.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o1777):
        raise ProfileError("workspace must be the recorded caller-owned sticky development directory")
    record = json.loads(read_private_file(profile.control / "workspace.json"), object_pairs_hook=unique_object)
    if record != {"schema": 1, "device": metadata.st_dev, "inode": metadata.st_ino}:
        raise ProfileError("workspace identity changed; never attach a replacement directory")


def trusted_binary(path):
    trusted_ancestors(Path(path))
    metadata = Path(path).lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_mode & 0o022 or not metadata.st_mode & 0o111):
        raise ProfileError(f"not a protected executable: {path}")


def check_assets(profile):
    if os.getuid() in {0, 65532}:
        raise ProfileError("use a dedicated non-root host operator, not the container UID")
    trusted_ancestors(profile.host_root)
    private_directory(profile.host_root)
    check_private_tree(profile.control)
    for name in ["policy.yaml", "broker.gitconfig"]:
        read_private_file(profile.control / name)
    for name in ["home", "grants", "records", "tmp", "docker", "credentials"]:
        private_directory(profile.control / name)
    if list((profile.control / "docker").iterdir()):
        raise ProfileError("Docker CLI configuration must stay empty; no proxy/env or credential plugins")
    check_workspace(profile)
    for binary in [profile.docker_binary, profile.broker_binary, "/usr/bin/git"]:
        trusted_binary(binary)
    trusted_ancestors(Path("/usr/bin"))
    metadata = Path("/usr/bin").lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ProfileError("fixed broker PATH is not host-protected")


def host_environment(profile):
    return {"PATH": "/usr/bin", "HOME": str(profile.control / "home"),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TMPDIR": str(profile.control / "tmp")}


def docker_prefix(profile):
    return [profile.docker_binary, "--host=unix:///var/run/docker.sock",
            "--config", str(profile.control / "docker")]


def docker_call(profile, arguments):
    try:
        output = subprocess.run(docker_prefix(profile) + arguments, env=host_environment(profile),
                                cwd=profile.control, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProfileError("Docker operation unavailable or timed out; no fallback") from error
    if output.returncode != 0:
        raise ProfileError(f"Docker {arguments[0]} failed; inspect the trusted daemon directly")
    return output.stdout


def docker_json(profile, arguments, one=False):
    try:
        value = json.loads(docker_call(profile, arguments))
    except json.JSONDecodeError as error:
        raise ProfileError("Docker returned invalid JSON") from error
    if one:
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise ProfileError("expected one Docker object")
        return value[0]
    if not isinstance(value, dict):
        raise ProfileError("expected a Docker information object")
    return value


def validate_daemon(info, host_kernel):
    options = info.get("SecurityOptions", [])
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        raise ProfileError("invalid Docker security metadata")
    if (info.get("OSType") != "linux" or info.get("KernelVersion") != host_kernel
            or "docker desktop" in str(info.get("OperatingSystem", "")).lower()
            or "name=seccomp,profile=builtin" not in options
            or any("rootless" in item or "userns" in item for item in options)):
        raise ProfileError("requires native Linux Docker with builtin seccomp and no UID remapping")
    if any(info.get(key) is not True for key in
           ["MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota", "PidsLimit"]):
        raise ProfileError("daemon does not report all required resource-limit capabilities")


def validate_image(profile, image):
    config = image.get("Config", {})
    if image.get("Id") != profile.image or config.get("Volumes"):
        raise ProfileError("image changed or declares additional volumes")
    entries = config.get("Env") or []
    if any(not isinstance(item, str) or "=" not in item
           or item.split("=", 1)[0] not in CONTAINER_ENV for item in entries):
        raise ProfileError("image has unsupported inherited environment; use a reviewed credential-free image")


def check_runtime(profile):
    if platform.system() != "Linux":
        raise ProfileError("strict deployment is native Linux only; no desktop VM or advisory fallback")
    socket = Path("/var/run/docker.sock").stat()
    if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
        raise ProfileError("requires the trusted local root-owned Docker Engine socket")
    validate_daemon(docker_json(profile, ["info", "--format", "{{json .}}"]), platform.release())
    image = docker_json(profile, ["image", "inspect", profile.image], one=True)
    validate_image(profile, image)


def create_command(profile):
    command = docker_prefix(profile) + [
        "create", "--name=" + profile.container_name,
        "--label=org.agent-guard.profile=broker-first-v1", "--pull=never", "--runtime=runc",
        "--read-only", "--user=" + AGENT_USER, "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true", "--network=bridge", "--ipc=private",
        "--cgroupns=private", "--pids-limit=256", "--memory=2g", "--memory-swap=2g",
        "--cpus=2", "--shm-size=64m", "--ulimit=nofile=1024:1024",
        "--restart=no", "--no-healthcheck", "--init", "--log-driver=local",
        "--log-opt=max-size=10m", "--log-opt=max-file=3", "--workdir=/workspace",
        f"--mount=type=bind,src={profile.workspace},dst=/workspace,bind-propagation=rprivate",
    ]
    command += [f"--tmpfs={path}:{options}" for path, options in SCRATCH.items()]
    command += [f"--env={key}={value}" for key, value in CONTAINER_ENV.items()]
    return command + ["--entrypoint=" + profile.agent_command[0], profile.image, *profile.agent_command[1:]]


def validate_container(profile, container):
    config, host = container.get("Config", {}), container.get("HostConfig", {})
    expected = {
        "Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "bridge",
        "IpcMode": "private", "CgroupnsMode": "private", "Runtime": "runc",
        "Memory": 2 * 1024**3, "MemorySwap": 2 * 1024**3, "NanoCpus": 2_000_000_000,
        "PidsLimit": 256, "PublishAllPorts": False, "ShmSize": 64 * 1024**2,
        "Init": True, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "Ulimits": [{"Name": "nofile", "Hard": 1024, "Soft": 1024}],
        "LogConfig": {"Type": "local", "Config": {"max-size": "10m", "max-file": "3"}},
    }
    if any(host.get(key) != value for key, value in expected.items()):
        raise ProfileError("container security/resource profile drifted")
    for key in ["Binds", "CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules", "GroupAdd",
                "ExtraHosts", "Links", "PortBindings", "Sysctls"]:
        if host.get(key):
            raise ProfileError(f"container has unsupported authority: {key}")
    if (host.get("PidMode") not in {"", "private"} or host.get("UsernsMode") != ""
            or host.get("UTSMode") not in {"", "private"} or host.get("CgroupParent")
            or host.get("CapDrop") != ["ALL"]
            or host.get("SecurityOpt") != ["no-new-privileges=true"]
            or host.get("Tmpfs") != SCRATCH
            or not MASKED_PATHS.issubset(host.get("MaskedPaths") or [])
            or not READONLY_PATHS.issubset(host.get("ReadonlyPaths") or [])):
        raise ProfileError("container namespace, capability, or filesystem protections drifted")
    mounts = container.get("Mounts", [])
    if (len(mounts) != 1 or mounts[0].get("Type") != "bind"
            or mounts[0].get("Source") != str(profile.workspace)
            or mounts[0].get("Destination") != "/workspace" or mounts[0].get("RW") is not True
            or mounts[0].get("Propagation") != "rprivate"):
        raise ProfileError("container must have exactly the dedicated workspace bind mount")
    if (container.get("Image") != profile.image or config.get("User") != AGENT_USER
            or config.get("WorkingDir") != "/workspace" or config.get("Tty") is not False
            or config.get("OpenStdin") is not False or config.get("AttachStdin") is not False
            or config.get("Volumes") or config.get("Healthcheck", {}).get("Test") != ["NONE"]
            or config.get("Entrypoint") != [profile.agent_command[0]]
            or config.get("Cmd") != list(profile.agent_command[1:])
            or config.get("Labels", {}).get("org.agent-guard.profile") != "broker-first-v1"
            or sorted(config.get("Env", [])) != sorted(f"{key}={value}" for key, value in CONTAINER_ENV.items())):
        raise ProfileError("container image, entrypoint, identity, terminal, or environment drifted")
    networks = container.get("NetworkSettings", {}).get("Networks", {})
    if set(networks) not in [set(), {"bridge"}]:
        raise ProfileError("additional container network detected")


def container_state(profile):
    value = docker_json(profile, ["container", "inspect", profile.container_name], one=True)
    validate_container(profile, value)
    return value.get("State", {})


def container_exists(profile):
    matches = docker_call(profile, ["container", "ls", "--all", "--filter",
                                   f"name=^/{profile.container_name}$", "--format", "{{.ID}}"])
    return bool(matches.strip())


def start_agent(profile):
    if not container_exists(profile):
        command = create_command(profile)
        docker_call(profile, command[len(docker_prefix(profile)):])
    state = container_state(profile)  # Inspect before any agent process starts.
    if state.get("Running"):
        raise ProfileError("agent already running")
    docker_call(profile, ["container", "start", profile.container_name])  # Never attach host terminal.


def require_host_tty(descriptors=(0, 1, 2)):
    """Necessary device checks only. OS/deployment permissions identify the approver."""
    names = []
    for descriptor in descriptors:
        if not os.isatty(descriptor):
            raise ProfileError("push requires a separate trusted host TTY; pipes and redirected streams are refused")
        metadata = os.fstat(descriptor)
        if (not stat.S_ISCHR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o022):
            raise ProfileError("approval terminal must be caller-owned and not group/world writable; use mesg n")
        names.append(os.ttyname(descriptor))
    if len(set(names)) != 1:
        raise ProfileError("approval streams must refer to the same host terminal")


def repository_destination(profile):
    git_dir = profile.workspace / ".git"
    if not stat.S_ISDIR(git_dir.lstat().st_mode):
        raise ProfileError("only a normal .git directory is supported")
    metadata = (git_dir / "config").lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ProfileError("repository config must be an ordinary single-link file")
    environment = host_environment(profile) | {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    for kind in ["pushurl", "url"]:
        output = subprocess.run(["/usr/bin/git", "config", "--file", str(git_dir / "config"),
                                 "--no-includes", "--null", "--get-all", f"remote.{profile.remote}.{kind}"],
                                env=environment, cwd=profile.control, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=15, check=False)
        if output.returncode == 1:
            continue
        if output.returncode != 0:
            raise ProfileError("repository destination could not be read")
        values = output.stdout.decode("utf-8").split("\0")
        if values[-1] == "":
            values.pop()
        if values != [profile.destination]:
            raise ProfileError("repository push destination must exactly equal the host-approved profile URL")
        return
    raise ProfileError("repository remote is missing")


def broker_command(profile, receipt):
    return [profile.broker_binary, "--ledger", str(profile.control / "ledger.jsonl"), "push",
            "--policy", str(profile.control / "policy.yaml"), "--repo", str(profile.workspace),
            "--remote", profile.remote, "--branch", profile.branch,
            "--git-config", str(profile.control / "broker.gitconfig"),
            "--grants", str(profile.control / "grants"), "--receipt", str(receipt)]


def push_from_host(profile):
    require_host_tty()  # Before stop, preview, credentials, or any broker invocation.
    check_assets(profile)
    check_runtime(profile)
    state = container_state(profile)
    if state.get("Running"):
        docker_call(profile, ["container", "stop", "--time=5", profile.container_name])
    if container_state(profile).get("Running") is not False:
        raise ProfileError("agent container did not stop; no push is permitted")
    check_workspace(profile)
    repository_destination(profile)
    receipt = profile.control / "records" / f"attempt-{uuid.uuid4().hex}.json"
    # No shell, no --yes, no agent request/grant field. Broker still previews,
    # confirms, issues a one-use grant, and revalidates the exact transaction.
    os.execve(profile.broker_binary, broker_command(profile, receipt), host_environment(profile))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init-workspace", "check", "start", "push"])
    parser.add_argument("--config", required=True, type=Path)
    options = parser.parse_args()
    if platform.system() != "Linux":
        print("broker-first: strict deployment requires native Linux; no files changed.", file=sys.stderr)
        return 2
    os.umask(0o077)
    try:
        profile = load_config(options.config)
        if options.action == "init-workspace":
            initialize_workspace(profile)
            print("Fresh workspace initialized; isolation acceptance has not run.")
        elif options.action == "push":
            push_from_host(profile)
        else:
            check_assets(profile)
            check_runtime(profile)
            if options.action == "start":
                start_agent(profile)
            elif container_exists(profile):
                container_state(profile)
            print(json.dumps({"configuration_check": "passed", "isolation_acceptance": "not_run",
                              "runtime": "native-linux-docker", "image": profile.image}))
        return 0
    except (ProfileError, OSError, UnicodeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"broker-first: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
