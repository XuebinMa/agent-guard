"""Pure driver/schema locks, not native container acceptance evidence."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("native_acceptance", Path(__file__).with_name("acceptance.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class DriverTests(unittest.TestCase):
    def network(self, gateway="172.17.0.1"):
        return {"Name": "bridge", "Driver": "bridge", "Scope": "local", "Internal": False,
                "IPAM": {"Config": [{"Subnet": "172.17.0.0/16", "Gateway": gateway}]}}

    def test_actual_private_default_gateway_is_selected(self):
        self.assertEqual(DRIVER.private_bridge_gateway(self.network()), "172.17.0.1")

    def test_no_public_disconnected_custom_or_ambiguous_network(self):
        invalid = [self.network("0.0.0.0"), self.network("127.0.0.1"),
                   self.network("8.8.8.8"), self.network("192.168.0.1")]
        for field, value in [("Name", "custom"), ("Driver", "host"), ("Scope", "swarm"), ("Internal", True)]:
            item = self.network()
            item[field] = value
            invalid.append(item)
        empty = self.network()
        empty["IPAM"]["Config"] = []
        invalid.append(empty)
        duplicate = self.network()
        duplicate["IPAM"]["Config"].append({"Subnet": "10.0.0.0/24", "Gateway": "10.0.0.1"})
        invalid.append(duplicate)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(AssertionError):
                DRIVER.private_bridge_gateway(item)

    def report(self):
        return {"schema": 1, "uid": 65532, "workspace_build": "fixture-ok", "local_oid": "a" * 40,
                "https_status": 401, "direct_push_status": 128,
                "protected_files_inaccessible": {str(index): True for index in range(5)},
                "authority_directories_unavailable": True, "docker_socket_unavailable": True,
                "host_cli_unavailable": True, "host_tty_unavailable": True,
                "agent_fake_record_is_only_workspace_data": True}

    def test_positive_public_fixture_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(json.dumps(self.report()))
            self.assertEqual(DRIVER.safe_report(path)["local_oid"], "a" * 40)

    def test_network_failure_or_missing_authority_negative_never_counts_as_success(self):
        mutations = [({"https_status": 0}), ({"https_status": 200}),
                     ({"direct_push_status": 0}), ({"direct_push_status": None}),
                     ({"direct_push_status": False}), ({"uid": 0}), ({"host_tty_unavailable": False}),
                     ({"docker_socket_unavailable": False}), ({"host_cli_unavailable": False}),
                     ({"protected_files_inaccessible": {"one": True}})]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            for mutation in mutations:
                report = self.report() | mutation
                path.write_text(json.dumps(report))
                with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                    DRIVER.safe_report(path)

    def test_evidence_symlink_is_not_a_fixture_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source").write_text(json.dumps(self.report()))
            (root / "report").symlink_to(root / "source")
            with self.assertRaises(AssertionError):
                DRIVER.safe_report(root / "report")

    def test_terminal_uses_one_private_device_and_real_prompt_before_answer(self):
        process = mock.Mock()
        process.poll.return_value = 0
        process.returncode = 0
        observed = []
        held = []

        def create(_arguments, **kwargs):
            descriptors = [kwargs[key] for key in ["stdin", "stdout", "stderr"]]
            self.assertEqual(len(set(descriptors)), 1)
            metadata = os.fstat(descriptors[0])
            self.assertTrue(stat.S_ISCHR(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertTrue(kwargs["start_new_session"])
            observed.extend(descriptors)
            # A real child keeps its duplicated slave open until it exits.
            held.append(os.dup(descriptors[0]))
            os.write(descriptors[0], b"Push this? [y/N] ")
            return process

        try:
            with mock.patch.object(DRIVER.subprocess, "Popen", side_effect=create):
                status, transcript = DRIVER.terminal_push(Path("/tmp/synthetic-config.json"), b"n\n")
        finally:
            for descriptor in held:
                os.close(descriptor)
        self.assertEqual(status, 0)
        self.assertIn(b"Push this? [y/N] ", transcript)
        with self.assertRaises(OSError):
            os.fstat(observed[0])

    def test_terminal_timeout_stops_only_its_own_process_group_and_closes_devices(self):
        process = mock.Mock()
        process.pid = 424242
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("synthetic-host-caller", 3), 0]
        opened = []
        original = DRIVER.pty.openpty

        def allocate():
            descriptors = original()
            opened.extend(descriptors)
            return descriptors

        with mock.patch.object(DRIVER.pty, "openpty", side_effect=allocate), \
                mock.patch.object(DRIVER.subprocess, "Popen", return_value=process), \
                mock.patch.object(DRIVER.time, "monotonic", side_effect=[0, 2]), \
                mock.patch.object(DRIVER.os, "killpg") as kill:
            with self.assertRaises(TimeoutError):
                DRIVER.terminal_push(Path("/tmp/synthetic-config.json"), b"y\n", timeout=1)
        self.assertEqual(kill.call_args_list,
                         [mock.call(424242, signal.SIGTERM), mock.call(424242, signal.SIGKILL)])
        for descriptor in opened:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_rejected_owned_container_is_removed_but_never_restarted_for_cleanup(self):
        profile = SimpleNamespace(image="sha256:" + "a" * 64, agent_command=("/usr/bin/python3", "fixture"),
                                  workspace=Path("/tmp/synthetic/workspace"), container_name="synthetic")
        actual = {"Id": "b" * 64, "Image": profile.image,
                  "Config": {"Labels": {"org.agent-guard.profile": "broker-first-v1"},
                             "Entrypoint": ["/usr/bin/python3"], "Cmd": ["fixture"]},
                  "Mounts": [{"Type": "bind", "Source": str(profile.workspace), "Destination": "/workspace"}]}
        launcher = mock.Mock()
        launcher.container_exists.return_value = True
        launcher.docker_json.return_value = actual
        launcher.validate_container.side_effect = ValueError("synthetic profile drift")
        self.assertFalse(DRIVER.cleanup_fixture(profile, launcher))
        launcher.docker_call.assert_called_once_with(profile, ["container", "rm", "--force", "b" * 64])

    def test_existing_report_cannot_hide_an_already_exited_requester(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "agent-evidence.json").write_text(json.dumps(self.report()))
            launcher = mock.Mock()
            launcher.container_state.return_value = {"Running": False}
            with self.assertRaises(AssertionError):
                DRIVER.wait_for_agent(SimpleNamespace(workspace=workspace), launcher)

    def test_launcher_timeout_terminates_its_sleeping_grandchild(self):
        # Harmless private host processes only: no shell, Docker, network,
        # privileges or payload. The parent's public output identifies its own
        # child; timeout must end the whole owned process group.
        program = ("import subprocess, sys, time; "
                   "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                   "print(child.pid, flush=True); time.sleep(30)")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                DRIVER.run([sys.executable, "-c", program], cwd=temporary, timeout=2)
            identifier = int(caught.exception.output.strip())
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                observed = subprocess.run(["/bin/ps", "-p", str(identifier), "-o", "stat="],
                                          capture_output=True, timeout=2, check=False)
                state = observed.stdout.decode().strip()
                if not state or state.startswith("Z"):
                    break
                time.sleep(0.05)
            else:
                self.fail("a harmless grandchild remained live after its launcher's timeout")


if __name__ == "__main__":
    unittest.main()
