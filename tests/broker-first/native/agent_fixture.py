"""Finite, synthetic agent workload for the native deployment acceptance job.

No general command runner: programs, source, paths and operations are fixed.
Public endpoint/CA and fixture-only host paths are the sole inputs. Authorization
material, the service key, broker and Docker socket are never supplied.
"""

import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import time
from urllib.parse import urlsplit


WORKSPACE = Path("/workspace")
REPORT = WORKSPACE / "agent-evidence.json"
C_SOURCE = '#include <stdio.h>\nint main(void) { puts("fixture-ok"); return 0; }\n'


def run(arguments, *, check=True):
    return subprocess.run(arguments, cwd=WORKSPACE, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=15, check=check)


def inaccessible_file(path):
    """Only synthetic named fixtures. Never returns bytes or writes content."""
    for flags in [os.O_RDONLY, os.O_WRONLY]:
        try:
            descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
        except (FileNotFoundError, PermissionError):
            continue
        else:
            os.close(descriptor)
            return False
    return True


def cleanup_owned_fixture():
    # These two ordinary trees are created exclusively by this fixed workload.
    # No imported repository, symlinks, or user data enter this fixture.
    for name in [".git", "build"]:
        path = WORKSPACE / name
        if path.is_symlink():
            raise RuntimeError("fixture cleanup refuses a replaced directory")
        if path.exists():
            shutil.rmtree(path)
    (WORKSPACE / "cleanup-complete").write_text("fixture-cleanup-complete\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", required=True)
    parser.add_argument("--host-root", required=True, type=Path)
    parser.add_argument("--host-broker", required=True)
    options = parser.parse_args()
    if (WORKSPACE / "cleanup-request").exists():
        cleanup_owned_fixture()
        return
    parsed = urlsplit(options.destination)
    if parsed.scheme != "https" or parsed.path != "/repo.git" or not parsed.hostname:
        raise RuntimeError("unexpected public fixture destination")
    if not (WORKSPACE / ".git").exists():
        run(["/usr/bin/git", "init", "-b", "main"])
        run(["/usr/bin/git", "config", "user.name", "Container Fixture"])
        run(["/usr/bin/git", "config", "user.email", "fixture@example.invalid"])
        (WORKSPACE / "hello.c").write_text(C_SOURCE)
        run(["/usr/bin/git", "add", "hello.c"])
        run(["/usr/bin/git", "commit", "-m", "harmless native fixture"])
        run(["/usr/bin/git", "remote", "add", "origin", options.destination])
    (WORKSPACE / "build").mkdir(exist_ok=True)
    run(["/usr/bin/gcc", "hello.c", "-o", "build/hello"])
    output = run([str(WORKSPACE / "build/hello")]).stdout.decode().strip()
    if output != "fixture-ok":
        raise RuntimeError("workspace build did not execute normally")
    oid = run(["/usr/bin/git", "rev-parse", "HEAD"]).stdout.decode().strip()
    connection = http.client.HTTPSConnection(
        parsed.hostname, parsed.port, timeout=5,
        context=ssl.create_default_context(cafile=WORKSPACE / "public-ca.pem"),
    )
    try:
        connection.request("GET", "/repo.git/info/refs?service=git-receive-pack")
        reachable_status = connection.getresponse().status
    finally:
        connection.close()
    if reachable_status != 401:
        raise RuntimeError("fixture must be reachable with verified TLS and refuse missing authentication")
    mutation = run(["/usr/bin/git", "-c", "http.sslCAInfo=/workspace/public-ca.pem",
                    "push", "origin", "main"], check=False)
    control = options.host_root / "control"
    protected = [control / "policy.yaml", control / "broker.gitconfig",
                 control / "grants/native-grant-canary.json",
                 control / "records/native-record-canary.json",
                 control / "home/host-only-canary"]
    path_checks = {str(path): inaccessible_file(path) for path in protected}
    authority_directories = all(not path.exists() for path in [
        control / "grants", control / "records", control / "credentials", control / "home",
    ])
    docker_socket = socket.socket(socket.AF_UNIX)
    docker_socket.settimeout(2)
    try:
        docker_socket.connect("/var/run/docker.sock")
    except (FileNotFoundError, PermissionError):
        socket_unavailable = True
    else:
        socket_unavailable = False
    finally:
        docker_socket.close()
    # Test actual unavailable host entrypoint, not an assumed different UID.
    try:
        run([options.host_broker, "push", "--yes"], check=False)
    except (FileNotFoundError, PermissionError):
        host_cli_unavailable = True
    else:
        host_cli_unavailable = False
    # A workspace lookalike is data, never the host's grant/record authority.
    fake = WORKSPACE / "agent-owned-lookalike.json"
    fake.write_text(json.dumps({"fixture": "not-an-authorization", "approved": True}))
    report = {
        "schema": 1, "uid": os.getuid(), "workspace_build": output, "local_oid": oid,
        "https_status": reachable_status, "direct_push_status": mutation.returncode,
        "protected_files_inaccessible": path_checks,
        "authority_directories_unavailable": authority_directories,
        "docker_socket_unavailable": socket_unavailable,
        "host_cli_unavailable": host_cli_unavailable,
        "host_tty_unavailable": not any(os.isatty(fd) for fd in [0, 1, 2]),
        "agent_fake_record_is_only_workspace_data": fake.is_file(),
    }
    temporary = WORKSPACE / "agent-evidence.tmp"
    temporary.write_text(json.dumps(report, sort_keys=True) + "\n")
    temporary.replace(REPORT)
    # The real launcher must stop a live requester before host approval. This
    # bounded idle interval is never used as evidence that a process is stopped.
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        time.sleep(0.2)
    raise RuntimeError("host acceptance driver did not stop the agent in time")


if __name__ == "__main__":
    main()
