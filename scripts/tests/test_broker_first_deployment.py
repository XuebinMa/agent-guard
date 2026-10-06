"""Fixed-profile deployment checks; no daemon, network, or shell payloads."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.name == "posix":
    import pty


SOURCE = Path(__file__).resolve().parents[2] / "deploy/broker-first/launch.py"
SPEC = importlib.util.spec_from_file_location("broker_first_launch", SOURCE)
deployment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = deployment
SPEC.loader.exec_module(deployment)


@unittest.skipUnless(os.name == "posix", "Linux profile uses POSIX permission/terminal fixtures; native Linux gate must run")
class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "host"
        self.root.mkdir(mode=0o700)
        (self.root / "control").mkdir(mode=0o700)
        self.raw = {
            "schema": 1,
            "host_root": str(self.root),
            "image": "sha256:" + "a" * 64,
            "docker_binary": "/usr/bin/docker",
            "broker_binary": "/opt/agent-guard/bin/agent-guard",
            "agent_command": ["/usr/bin/python3", "/opt/agent/main.py"],
            "destination": "https://example.invalid/team/repo.git",
            "remote": "origin",
            "branch": "main",
        }
        self.config_path = self.root / "control/deployment.json"
        self.write(self.config_path, json.dumps(self.raw))
        self.profile = deployment.validate_config(self.raw)

    def write(self, path, content):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    def prepare(self):
        self.write(self.root / "control/policy.yaml", "default_mode: workspace-write\n")
        self.write(self.root / "control/broker.gitconfig", "# anonymous fixture only\n")
        deployment.initialize_workspace(self.profile)

    def test_unknown_privilege_mount_environment_and_host_tool_keys_are_rejected(self):
        for key, value in {
            "privileged": True,
            "mounts": ["/var/run/docker.sock:/var/run/docker.sock"],
            "environment": {"SSH_AUTH_SOCK": "/fixture/socket"},
            "host_handlers": ["fixture"],
            "network": "host",
            "user": "0",
            "yes": True,
        }.items():
            with self.subTest(key=key):
                raw = dict(self.raw, **{key: value})
                with self.assertRaises(deployment.ProfileError):
                    deployment.validate_config(raw)

    def test_schema_and_values_are_strict(self):
        for key, value in [
            ("schema", True), ("schema", 2),
            ("image", "ubuntu:latest"),
            ("host_root", "relative"),
            ("host_root", "/"),
            ("host_root", "/fixture,extra"),
            ("docker_binary", "docker"),
            ("broker_binary", "/opt/other-cli"),
            ("agent_command", ["/usr/bin/python3"]),
            ("agent_command", ["python3", "fixture.py"]),
            ("agent_command", ["/usr/bin/python3", "line\nargument"]),
            ("remote", "_origin"),
            ("remote", "origin;fixture"),
            ("branch", "main..old"),
            ("branch", "-main"),
            ("branch", "main.lock"),
            ("destination", "http://example.invalid/repo.git"),
            ("destination", "https://user@example.invalid/repo.git"),
            ("destination", "https://example.invalid/%72epo.git"),
            ("destination", "https://example.invalid/repo.git?other=1"),
        ]:
            with self.subTest(key=key, value=value):
                raw = dict(self.raw, **{key: value})
                with self.assertRaises(deployment.ProfileError):
                    deployment.validate_config(raw)

    def test_duplicate_json_keys_are_not_last_value_wins(self):
        self.write(self.config_path, '{"schema": 1, "schema": 1}')
        with self.assertRaises(deployment.ProfileError):
            deployment.load_config(self.config_path)

    def test_unsupported_host_cli_refuses_before_config_reads_or_initialization(self):
        for system in ["Darwin", "Windows"]:
            with self.subTest(system=system), \
                    patch.object(deployment.platform, "system", return_value=system), \
                    patch.object(sys, "argv", ["launch.py", "init-workspace", "--config", "/fixture"]), \
                    patch.object(deployment, "load_config") as load, \
                    patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(deployment.main(), 2)
                load.assert_not_called()

    def test_normal_configuration_loads_and_workspace_is_fresh(self):
        loaded = deployment.load_config(self.config_path)
        self.assertEqual(loaded, self.profile)
        self.prepare()
        self.assertEqual(list(self.profile.workspace.iterdir()), [])
        self.assertEqual(self.profile.workspace.stat().st_mode & 0o7777, 0o1777)
        deployment.check_workspace(self.profile)
        with self.assertRaises(deployment.ProfileError):
            deployment.initialize_workspace(self.profile)

    def test_workspace_identity_cannot_be_replaced(self):
        self.prepare()
        self.profile.workspace.rename(self.profile.workspace.with_name("saved"))
        self.profile.workspace.mkdir(mode=0o1777)
        with self.assertRaises(deployment.ProfileError):
            deployment.check_workspace(self.profile)

    def test_sensitive_files_reject_links_and_writable_permissions(self):
        linked = self.root / "control/linked.json"
        linked.symlink_to(self.config_path)
        with self.assertRaises(deployment.ProfileError):
            deployment.read_private_file(linked)
        hardlink = self.root / "control/hardlink.json"
        os.link(self.config_path, hardlink)
        with self.assertRaises(deployment.ProfileError):
            deployment.read_private_file(self.config_path)
        hardlink.unlink()
        self.config_path.chmod(0o666)
        with self.assertRaises(deployment.ProfileError):
            deployment.read_private_file(self.config_path)

    def test_create_is_fixed_nonprivileged_and_only_mounts_the_fresh_workspace(self):
        self.prepare()
        command = deployment.create_command(self.profile)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges=true", command)
        self.assertIn("--network=bridge", command)
        self.assertIn("--user=65532:65532", command)
        self.assertIn("--pull=never", command)
        self.assertIn("--env=GIT_CONFIG_KEY_0=safe.directory", command)
        self.assertIn("--env=GIT_CONFIG_VALUE_0=/workspace", command)
        mounts = [value for value in command if value.startswith("--mount=")]
        self.assertEqual(mounts, [
            f"--mount=type=bind,src={self.profile.workspace},dst=/workspace,bind-propagation=rprivate"
        ])
        for forbidden in ["--privileged", "--pid=host", "--network=host", "--interactive", "--tty"]:
            self.assertNotIn(forbidden, command)
        self.assertEqual(command[-3:], [
            "--entrypoint=/usr/bin/python3", self.profile.image, "/opt/agent/main.py"
        ])

    def test_host_environment_contains_no_ambient_credentials_or_overrides(self):
        environment = deployment.host_environment(self.profile)
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["HOME"], str(self.profile.control / "home"))
        for forbidden in ["SSH_AUTH_SOCK", "DOCKER_HOST", "GIT_CONFIG_COUNT", "LD_PRELOAD", "PYTHONPATH", "GITHUB_TOKEN"]:
            self.assertNotIn(forbidden, environment)

    def test_native_daemon_and_builtin_seccomp_are_required(self):
        good = {
            "OSType": "linux", "KernelVersion": "fixture-kernel",
            "OperatingSystem": "Ubuntu", "SecurityOptions": ["name=seccomp,profile=builtin"],
            "MemoryLimit": True, "SwapLimit": True, "CpuCfsPeriod": True,
            "CpuCfsQuota": True, "PidsLimit": True,
        }
        deployment.validate_daemon(good, "fixture-kernel")
        for change in [
            {"OSType": "windows"}, {"KernelVersion": "other-kernel"},
            {"OperatingSystem": "Docker Desktop"}, {"SecurityOptions": []},
            {"SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless"]},
            {"SecurityOptions": ["name=seccomp,profile=builtin", "name=userns"]},
            {"MemoryLimit": False}, {"PidsLimit": False},
        ]:
            with self.subTest(change=change):
                with self.assertRaises(deployment.ProfileError):
                    deployment.validate_daemon(dict(good, **change), "fixture-kernel")

    def test_image_cannot_add_inherited_mounts_or_environment(self):
        good = {"Id": self.profile.image, "Config": {"Env": ["PATH=/usr/bin"], "Volumes": None}}
        deployment.validate_image(self.profile, good)
        for field, value in [("Env", ["GITHUB_TOKEN=public-fixture"]),
                             ("Env", ["LD_PRELOAD=/fixture"]),
                             ("Volumes", {"/host": {}})]:
            bad = copy.deepcopy(good)
            bad["Config"][field] = value
            with self.assertRaises(deployment.ProfileError):
                deployment.validate_image(self.profile, bad)

    def container(self):
        return {
            "Image": self.profile.image,
            "Config": {
                "User": "65532:65532", "WorkingDir": "/workspace",
                "Tty": False, "OpenStdin": False, "AttachStdin": False, "Volumes": None,
                "Entrypoint": [self.profile.agent_command[0]],
                "Cmd": list(self.profile.agent_command[1:]), "Healthcheck": {"Test": ["NONE"]},
                "Labels": {"org.agent-guard.profile": "broker-first-v1"},
                "Env": [f"{key}={value}" for key, value in deployment.CONTAINER_ENV.items()],
            },
            "HostConfig": {
                "Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "bridge",
                "IpcMode": "private", "CgroupnsMode": "private", "Runtime": "runc",
                "Memory": 2 * 1024**3, "MemorySwap": 2 * 1024**3, "NanoCpus": 2_000_000_000,
                "PidsLimit": 256, "PublishAllPorts": False, "ShmSize": 64 * 1024**2,
                "Init": True, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Ulimits": [{"Name": "nofile", "Hard": 1024, "Soft": 1024}],
                "LogConfig": {"Type": "local", "Config": {"max-size": "10m", "max-file": "3"}},
                "PidMode": "", "UsernsMode": "", "UTSMode": "", "CgroupParent": "",
                "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
                "Tmpfs": dict(deployment.SCRATCH),
                "MaskedPaths": sorted(deployment.MASKED_PATHS),
                "ReadonlyPaths": sorted(deployment.READONLY_PATHS),
            },
            "Mounts": [{"Type": "bind", "Source": str(self.profile.workspace),
                        "Destination": "/workspace", "RW": True, "Propagation": "rprivate"}],
            "NetworkSettings": {"Networks": {"bridge": {}}}, "State": {"Running": False},
        }

    def test_existing_container_profile_must_match_before_start_or_push(self):
        good = self.container()
        deployment.validate_container(self.profile, good)
        for field, value in [
            ("Privileged", True), ("ReadonlyRootfs", False), ("NetworkMode", "host"),
            ("PidMode", "host"), ("IpcMode", "host"), ("UTSMode", "host"),
            ("SecurityOpt", ["no-new-privileges=true", "seccomp=unconfined"]),
            ("MaskedPaths", ["/fixture"]), ("ReadonlyPaths", ["/fixture"]),
            ("CapAdd", ["SYS_ADMIN"]), ("GroupAdd", ["fixture"]),
            ("RestartPolicy", {"Name": "always", "MaximumRetryCount": 0}),
        ]:
            with self.subTest(field=field):
                bad = copy.deepcopy(good)
                bad["HostConfig"][field] = value
                with self.assertRaises(deployment.ProfileError):
                    deployment.validate_container(self.profile, bad)
        for field, value in [("OpenStdin", True), ("Tty", True),
                             ("Env", ["GITHUB_TOKEN=public-fixture"]),
                             ("Healthcheck", {"Test": ["fixture"]})]:
            bad = copy.deepcopy(good)
            bad["Config"][field] = value
            with self.assertRaises(deployment.ProfileError):
                deployment.validate_container(self.profile, bad)
        bad = copy.deepcopy(good)
        bad["Mounts"].append({"Type": "bind", "Source": "/fixture/socket",
                              "Destination": "/fixture/socket", "RW": True})
        with self.assertRaises(deployment.ProfileError):
            deployment.validate_container(self.profile, bad)
        bad = copy.deepcopy(good)
        bad["NetworkSettings"]["Networks"]["other"] = {}
        with self.assertRaises(deployment.ProfileError):
            deployment.validate_container(self.profile, bad)

    def test_git_push_url_is_checked_as_local_data_without_network(self):
        self.prepare()
        git_dir = self.profile.workspace / ".git"
        git_dir.mkdir()
        config = git_dir / "config"
        self.write(config, f'[remote "origin"]\nurl = https://other.invalid/repo.git\n'
                           f'pushurl = {self.profile.destination}\n')
        deployment.repository_destination(self.profile)
        self.write(config, f'[remote "origin"]\nurl = {self.profile.destination}\n')
        deployment.repository_destination(self.profile)
        for content in [
            '[remote "origin"]\nurl = https://other.invalid/repo.git\n',
            f'[remote "origin"]\npushurl = {self.profile.destination}\npushurl = {self.profile.destination}\n',
            '# missing remote\n',
        ]:
            self.write(config, content)
            with self.assertRaises(deployment.ProfileError):
                deployment.repository_destination(self.profile)
        config.unlink()
        config.symlink_to(self.config_path)
        with self.assertRaises(deployment.ProfileError):
            deployment.repository_destination(self.profile)

    def test_nonterminal_approval_is_refused(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        with self.assertRaises(deployment.ProfileError):
            deployment.require_host_tty((read_fd, write_fd, write_fd))

    def test_terminal_refusal_precedes_any_host_or_runtime_activity(self):
        with patch.object(deployment, "require_host_tty", side_effect=deployment.ProfileError("no terminal")), \
                patch.object(deployment, "check_assets") as assets, \
                patch.object(deployment, "check_runtime") as runtime, \
                patch.object(deployment.os, "execve") as execute:
            with self.assertRaises(deployment.ProfileError):
                deployment.push_from_host(self.profile)
            assets.assert_not_called()
            runtime.assert_not_called()
            execute.assert_not_called()

    def test_container_drift_refuses_start_before_any_agent_process(self):
        bad = self.container()
        bad["HostConfig"]["Privileged"] = True
        with patch.object(deployment, "docker_call", return_value="fixture-id\n") as call, \
                patch.object(deployment, "docker_json", return_value=bad):
            with self.assertRaises(deployment.ProfileError):
                deployment.start_agent(self.profile)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.args[1][:2], ["container", "ls"])

    def test_failed_stop_cannot_read_the_repository_or_invoke_broker(self):
        with patch.object(deployment, "require_host_tty"), \
                patch.object(deployment, "check_assets"), patch.object(deployment, "check_runtime"), \
                patch.object(deployment, "container_state", side_effect=[{"Running": True}, {"Running": True}]), \
                patch.object(deployment, "docker_call") as call, \
                patch.object(deployment, "repository_destination") as repository, \
                patch.object(deployment.os, "execve") as execute:
            with self.assertRaises(deployment.ProfileError):
                deployment.push_from_host(self.profile)
            self.assertEqual(call.call_args.args[1][:2], ["container", "stop"])
            repository.assert_not_called()
            execute.assert_not_called()

    def test_successful_orchestration_uses_fixed_existing_broker_without_yes(self):
        self.prepare()
        git_dir = self.profile.workspace / ".git"
        git_dir.mkdir()
        self.write(git_dir / "config", f'[remote "origin"]\nurl = {self.profile.destination}\n')
        # Only the daemon/terminal/executable boundary is substituted. Real
        # workspace identity and Git config reading remain exercised above.
        with patch.object(deployment, "require_host_tty"), \
                patch.object(deployment, "check_assets"), patch.object(deployment, "check_runtime"), \
                patch.object(deployment, "container_state", return_value={"Running": False}), \
                patch.object(deployment.os, "execve") as execute:
            deployment.push_from_host(self.profile)
            binary, arguments, environment = execute.call_args.args
            self.assertEqual(binary, self.profile.broker_binary)
            self.assertNotIn("--yes", arguments)
            self.assertEqual(environment, deployment.host_environment(self.profile))
            receipt = Path(arguments[arguments.index("--receipt") + 1])
            self.assertEqual(receipt.parent, self.profile.control / "records")

    def test_terminal_device_checks_are_not_an_approver_identity_proof(self):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        os.fchmod(slave, 0o600)
        deployment.require_host_tty((slave, slave, slave))
        os.fchmod(slave, 0o620)
        with self.assertRaises(deployment.ProfileError):
            deployment.require_host_tty((slave, slave, slave))

    def test_push_command_has_no_passthrough_yes_or_local_remote_option(self):
        command = deployment.broker_command(self.profile, self.profile.control / "records/fixture.json")
        self.assertEqual(command[0], self.profile.broker_binary)
        self.assertIn("push", command)
        for forbidden in ["--yes", "--allow-local-file-remote"]:
            self.assertNotIn(forbidden, command)
        self.assertEqual(command[command.index("--repo") + 1], str(self.profile.workspace))
        self.assertEqual(command[command.index("--grants") + 1], str(self.profile.control / "grants"))


if __name__ == "__main__":
    unittest.main()
