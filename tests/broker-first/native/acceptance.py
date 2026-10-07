#!/usr/bin/env python3
"""Required native Linux acceptance; unavailable runtime fails, never skips.

Invokes the frozen deployment launcher, not a parallel broker implementation.
Only the disposable image, local synthetic service, repositories and PTYs are
used. Run in a dedicated CI machine with no production credentials or agents.
"""

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time


REPOSITORY = Path(__file__).resolve().parents[3]
LAUNCHER = REPOSITORY / "deploy/broker-first/launch.py"
sys.path.insert(0, str(REPOSITORY / "tests/broker-first"))
from local_git_service import LocalGitService  # noqa: E402


def load_launcher():
    specification = importlib.util.spec_from_file_location("native_profile", LAUNCHER)
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(arguments, *, cwd, timeout=30, input=None):
    process = subprocess.Popen(
        arguments, cwd=cwd, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin", "LC_ALL": "C.UTF-8"}, start_new_session=True,
    )
    try:
        output, error = process.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        # The launcher may currently own a Docker CLI child. Killing only the
        # Python parent discards its 30s watchdog and can orphan that operation.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=3)
        raise
    require(len(output) + len(error) <= 1024 * 1024, "host fixture subprocess output exceeded its limit")
    return subprocess.CompletedProcess(arguments, process.returncode, output, error)


def private_text(path, content):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


def private_bridge_gateway(network):
    """Only the daemon's actual private default bridge, not an arbitrary IP."""
    require(network.get("Name") == "bridge" and network.get("Driver") == "bridge"
            and network.get("Scope") == "local" and not network.get("Internal"),
            "requires the native default bridge with network access")
    entries = network.get("IPAM", {}).get("Config", [])
    candidates = []
    for entry in entries:
        try:
            address = ipaddress.ip_address(entry["Gateway"])
            subnet = ipaddress.ip_network(entry["Subnet"])
        except (KeyError, ValueError):
            continue
        if address.version == 4:
            private_ranges = [ipaddress.ip_network(value) for value in
                              ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]
            require(address in subnet and any(address in block for block in private_ranges),
                    "default bridge gateway must be a local RFC1918 IPv4 address")
            candidates.append(str(address))
    require(len(candidates) == 1, "default bridge needs exactly one private IPv4 gateway")
    return candidates[0]


def safe_report(path):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 16384,
            "agent fixture did not provide a bounded ordinary evidence file")
    report = json.loads(path.read_text())
    require(report.get("schema") == 1 and report.get("uid") == 65532,
            "agent workload did not run as the fixed unprivileged identity")
    require(report.get("workspace_build") == "fixture-ok"
            and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", report.get("local_oid", "")),
            "ordinary workspace build and commit failed")
    require(report.get("https_status") == 401 and type(report.get("direct_push_status")) is int
            and report["direct_push_status"] != 0,
            "must observe reachable HTTPS authentication refusal, not a disconnected agent")
    checks = report.get("protected_files_inaccessible", {})
    require(len(checks) == 5 and all(value is True for value in checks.values()),
            "a named synthetic host authority file was reachable")
    for key in ["authority_directories_unavailable", "docker_socket_unavailable",
                "host_cli_unavailable", "host_tty_unavailable", "agent_fake_record_is_only_workspace_data"]:
        require(report.get(key) is True, f"native negative failed: {key}")
    return report


def wait_for_agent(profile, launcher, timeout=40):
    deadline = time.monotonic() + timeout
    report = profile.workspace / "agent-evidence.json"
    while time.monotonic() < deadline:
        require(launcher.container_state(profile).get("Running") is True,
                "agent stopped before native probes completed")
        if report.exists():
            return safe_report(report)
        time.sleep(0.2)
    raise TimeoutError("bounded agent workload did not publish its report")


def launcher_call(action, configuration, timeout=45, input=None):
    return run(["/usr/bin/python3", str(LAUNCHER), action, "--config", str(configuration)],
               cwd=configuration.parent, timeout=timeout, input=input)


def terminal_push(configuration, answer, timeout=60):
    """Synthetic trusted-host approval, never proof of a human identity."""
    master, slave = pty.openpty()
    os.fchmod(slave, 0o600)
    process = None
    transcript = bytearray()
    answered = False
    try:
        process = subprocess.Popen(
            ["/usr/bin/python3", str(LAUNCHER), "push", "--config", str(configuration)],
            cwd=configuration.parent, env={"PATH": "/usr/bin", "LC_ALL": "C.UTF-8"},
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
        )
        os.close(slave)
        slave = -1
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    content = os.read(master, 4096)
                except OSError:
                    content = b""
                transcript.extend(content)
                require(len(transcript) <= 65536, "native PTY output exceeded its bounded fixture log")
                if not answered and b"Push this? [y/N] " in transcript:
                    os.write(master, answer)
                    answered = True
            if process.poll() is not None:
                require(answered, "trusted-host broker did not reach its real confirmation prompt")
                return process.returncode, bytes(transcript)
        raise TimeoutError("host broker PTY did not finish in time")
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        os.close(master)
        if slave >= 0:
            os.close(slave)


def cleanup_fixture(profile, launcher):
    """Remove only this labelled fixture; retain its tree if UID cleanup fails."""
    if not launcher.container_exists(profile):
        return True
    actual = launcher.docker_json(profile, ["container", "inspect", profile.container_name], one=True)
    configuration = actual.get("Config", {})
    mounts = actual.get("Mounts", [])
    require(actual.get("Image") == profile.image
            and configuration.get("Labels", {}).get("org.agent-guard.profile") == "broker-first-v1"
            and configuration.get("Entrypoint") == [profile.agent_command[0]]
            and configuration.get("Cmd") == list(profile.agent_command[1:])
            and len(mounts) == 1 and mounts[0].get("Type") == "bind"
            and mounts[0].get("Source") == str(profile.workspace)
            and mounts[0].get("Destination") == "/workspace"
            and re.fullmatch(r"[a-f0-9]{64}", actual.get("Id", "")),
            "cleanup refuses any object not belonging to the exact synthetic workload")
    identifier = actual["Id"]
    try:
        # A production profile rejected at start must never be restarted merely
        # to clean up. Ownership permits removal, not a weaker execution mode.
        launcher.validate_container(profile, actual)
    except (ValueError, TypeError, KeyError):
        launcher.docker_call(profile, ["container", "rm", "--force", identifier])
        return False
    completed = False
    try:
        launcher.docker_call(profile, ["container", "stop", "--time=5", identifier])
        private_text(profile.workspace / "cleanup-request", "fixed synthetic fixture only\n")
        launcher.docker_call(profile, ["container", "start", identifier])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            state = launcher.docker_json(profile, ["container", "inspect", identifier], one=True)["State"]
            if state.get("Running") is False:
                marker = profile.workspace / "cleanup-complete"
                completed = (state.get("ExitCode") == 0 and not marker.is_symlink()
                             and marker.is_file() and marker.stat().st_size <= 128
                             and marker.read_text() == "fixture-cleanup-complete\n")
                break
            time.sleep(0.2)
    finally:
        # An image/profile acceptance failure still leaves a synthetic workload
        # with verified ownership. Never keep it running after a failed job.
        launcher.docker_call(profile, ["container", "rm", "--force", identifier])
    return completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="already-built exact sha256 image ID")
    parser.add_argument("--broker", required=True, type=Path, help="fresh checkout's built CLI")
    parser.add_argument("--evidence", required=True, type=Path, help="private JSON output outside the agent workspace")
    options = parser.parse_args()
    require(platform.system() == "Linux" and os.getuid() not in {0, 65532},
            "native acceptance requires the non-root Linux host operator; no desktop fallback")
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", options.image), "exact local image ID required")
    require(options.broker.is_file(), "freshly built host broker is missing")
    os.umask(0o077)
    launcher = load_launcher()
    root = Path(tempfile.mkdtemp(prefix="agent-guard-native-", dir="/tmp"))
    host = root / "deployment"
    control = host / "control"
    control.mkdir(parents=True, mode=0o700)
    (control / "docker").mkdir(mode=0o700)
    binary_directory = root / "bin"
    binary_directory.mkdir(mode=0o700)
    broker = binary_directory / "agent-guard"
    shutil.copyfile(options.broker, broker)
    broker.chmod(0o700)
    service_directory = root / "service"
    service_directory.mkdir(mode=0o700)
    configuration = control / "deployment.json"
    docker = ["/usr/bin/docker", "--host=unix:///var/run/docker.sock", "--config", str(control / "docker")]
    service = None
    profile = None
    cleanup_complete = False
    evidence = {"schema": 1, "runtime": "native-linux-docker", "image": options.image,
                "kernel": platform.release(), "operator_uid": os.getuid(), "accepted": False}
    require(not options.evidence.absolute().is_relative_to(root),
            "evidence must stay outside the agent's temporary deployment tree")
    try:
        network = run(docker + ["network", "inspect", "bridge"], cwd=control)
        require(network.returncode == 0, "native Docker default bridge inspection failed")
        networks = json.loads(network.stdout)
        require(isinstance(networks, list) and len(networks) == 1, "expected exactly one default bridge")
        gateway = private_bridge_gateway(networks[0])
        # The shared fixture independently checks Linux docker0's local address;
        # it never binds all interfaces, a public address, or an arbitrary host.
        service = LocalGitService(service_directory, docker_bridge_address=gateway)
        service.trusted_config(control / "broker.gitconfig")
        private_text(control / "policy.yaml", "version: 1\ndefault_mode: workspace_write\n"
                     "tools:\n  bash:\n    ask:\n      - prefix: 'git push'\n"
                     "audit:\n  enabled: false\nanomaly:\n  enabled: false\n")
        raw = {"schema": 1, "host_root": str(host), "image": options.image,
               "docker_binary": "/usr/bin/docker", "broker_binary": str(broker),
               "agent_command": ["/usr/bin/python3", "/opt/agent/fixture.py",
                                 "--destination", service.url, "--host-root", str(host),
                                 "--host-broker", str(broker)],
               "destination": service.url, "remote": "origin", "branch": "main"}
        private_text(configuration, json.dumps(raw, sort_keys=True) + "\n")
        initialized = launcher_call("init-workspace", configuration)
        require(initialized.returncode == 0, "frozen launcher workspace initialization failed")
        profile = launcher.load_config(configuration)
        for relative in ["grants/native-grant-canary.json", "records/native-record-canary.json",
                         "home/host-only-canary"]:
            private_text(control / relative, '{"fixture":"host-only-public-canary"}\n')
        shutil.copyfile(service.cert, profile.workspace / "public-ca.pem")
        (profile.workspace / "public-ca.pem").chmod(0o644)
        checked = launcher_call("check", configuration)
        require(checked.returncode == 0, "frozen launcher rejected the actual native runtime/image")
        started = launcher_call("start", configuration)
        require(started.returncode == 0, "frozen launcher refused its actual created container profile")
        report = wait_for_agent(profile, launcher)
        require(launcher.container_state(profile).get("Running") is True, "requester is not live")
        require(service.tip() is None and len(service.requests) >= 2
                and not any(auth for _, _, auth in service.requests),
                "direct agent mutation did not fail solely at the local authentication boundary")
        require(not (control / "ledger.jsonl").exists()
                and not list((control / "records").glob("attempt-*.json")),
                "workspace lookalike acquired host record authority")
        before = list(service.requests)
        refused = launcher_call("push", configuration, input=b"y\n")
        require(refused.returncode != 0 and b"trusted host TTY" in refused.stderr,
                "strict host entry accepted piped approval")
        require(service.requests == before and service.tip() is None
                and launcher.container_state(profile).get("Running") is True,
                "non-TTY rejection stopped the agent or touched the network/remote")
        for answer in [b"n\n", b"\x04"]:
            status, transcript = terminal_push(configuration, answer)
            require(status != 0 and service.url.encode() in transcript, "host cancellation/EOF was not shown")
            require(launcher.container_state(profile).get("Running") is False,
                    "strict host launcher did not stop the live agent before cancellation")
            require(service.tip() is None and not list((control / "records").glob("attempt-*.json")),
                    "cancel/EOF changed the remote or produced an execution receipt")
            require(not any(path.endswith("git-receive-pack") for _, path, _ in service.requests),
                    "cancel/EOF performed a receive-pack mutation attempt")
            (profile.workspace / "agent-evidence.json").unlink()
            restarted = launcher_call("start", configuration)
            require(restarted.returncode == 0, "P3 could not restart its stopped agent")
            require(wait_for_agent(profile, launcher)["local_oid"] == report["local_oid"],
                    "fixture restart unexpectedly changed the approved candidate")
        status, transcript = terminal_push(configuration, b"y\n")
        require(status == 0 and service.url.encode() in transcript, "trusted host approved push failed")
        require(launcher.container_state(profile).get("Running") is False,
                "requester remained live across host-authorized execution")
        receipts = list((control / "records").glob("attempt-*.json"))
        require(len(receipts) == 1, "expected exactly one host execution receipt")
        receipt = json.loads(launcher.read_private_file(receipts[0]))
        require(receipt["transaction"]["remote_url"] == service.url
                and receipt["transaction"]["local_oid"] == report["local_oid"]
                and receipt["transaction"]["branch"] == "main"
                and receipt["attempt"]["outcome"] == "pushed" and receipt["grant_id"]
                and receipt["witness"]["kind"] == "unsigned"
                and service.tip() == report["local_oid"], "receipt diverged from independent actual remote state")
        require((control / "grants/spent" / (receipt["grant_id"] + ".json")).is_file(),
                "successful receipt did not name an actually consumed host grant")
        # No raw terminal transcript, client headers, auth values, key or config
        # content is retained in CI artifacts, even though all are synthetic.
        version = run([str(broker), "--version"], cwd=control)
        require(version.returncode == 0, "broker version evidence failed")
        revision = run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=REPOSITORY)
        require(revision.returncode == 0, "checkout SHA evidence failed")
        actual = launcher.docker_json(profile, ["container", "inspect", profile.container_name], one=True)
        daemon = launcher.docker_json(profile, ["info", "--format", "{{json .}}"])
        with broker.open("rb") as binary:
            binary_digest = hashlib.file_digest(binary, "sha256").hexdigest()
        evidence.update({"accepted": True, "checkout_sha": revision.stdout.decode().strip(),
                         "broker_version": version.stdout.decode().strip(),
                         "broker_sha256": binary_digest,
                         "container_id": actual["Id"], "profile": "broker-first-v1",
                         "docker_server_version": daemon.get("ServerVersion"),
                         "docker_security_options": daemon.get("SecurityOptions"),
                         "configuration": raw, "container_host_config": actual["HostConfig"],
                         "container_mounts": actual["Mounts"], "agent": report,
                         "remote_url": service.url, "remote_oid": service.tip(),
                         "receipt_grant_id": receipt["grant_id"],
                         "checks": ["I5", "I6", "I8", "I7-success"],
                         "limits": ["PTY approval is synthetic, not human workflow acceptance",
                                    "I1-I4/I7-negative require the separate mandatory broker suites",
                                    "R1 Windows handles and R2 shared hard links remain open"]})
    except Exception as error:
        evidence["failure_type"] = type(error).__name__
        raise
    finally:
        try:
            cleanup_complete = profile is None or cleanup_fixture(profile, launcher)
        except Exception as error:
            evidence["cleanup_error_type"] = type(error).__name__
        try:
            if service is not None:
                service.close()
        except Exception as error:
            evidence["service_cleanup_error_type"] = type(error).__name__
            cleanup_complete = False
        # Preserve evidence on every ordinary failure. No raw subprocess output
        # or token is written; a failed job must not be interpreted as accepted.
        evidence["cleanup_complete"] = cleanup_complete
        if not evidence["cleanup_complete"]:
            evidence["accepted"] = False
        options.evidence.parent.mkdir(parents=True, exist_ok=True)
        private_text(options.evidence, json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        if evidence["cleanup_complete"]:
            shutil.rmtree(root)
    require(evidence["cleanup_complete"], "fixture cleanup failed; synthetic temporary tree retained")
    print("Native broker-first I5/I6/I8 and successful I7 passed; evidence saved without authentication material.")


if __name__ == "__main__":
    main()
