"""Local authenticated composition tests; not container-isolation evidence.

Run explicitly with a freshly built CLI:
AGENT_GUARD_TEST_CLI=/absolute/target/debug/agent-guard \
    python3 -m unittest discover -s tests/broker-first -v
"""

import http.client
import json
import os
from pathlib import Path
import ssl
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from local_git_service import LocalGitService, git_env, run_git


class FixtureBindTests(unittest.TestCase):
    def test_bridge_extension_refuses_public_wildcard_linklocal_and_noncanonical_addresses(self):
        from local_git_service import docker_bridge_listener
        for address in ["0.0.0.0", "8.8.8.8", "169.254.1.1", "127.0.0.1", "::1", "172.017.0.1"]:
            with self.subTest(address=address), mock.patch("local_git_service.subprocess.run") as command:
                with self.assertRaises(ValueError):
                    docker_bridge_listener(address)
                command.assert_not_called()

    def test_bridge_extension_requires_native_linux_and_the_named_local_interface(self):
        from local_git_service import docker_bridge_listener
        with mock.patch("local_git_service.platform.system", return_value="Darwin"):
            with self.assertRaises(ValueError):
                docker_bridge_listener("172.17.0.1")
        wrong = subprocess.CompletedProcess([], 0, stdout=json.dumps([
            {"addr_info": [{"family": "inet", "local": "172.18.0.1"}]}
        ]), stderr="")
        with mock.patch("local_git_service.platform.system", return_value="Linux"), \
                mock.patch("local_git_service.shutil.which", return_value="/usr/sbin/ip"), \
                mock.patch("local_git_service.subprocess.run", return_value=wrong):
            with self.assertRaises(ValueError):
                docker_bridge_listener("172.17.0.1")

    def test_bridge_extension_accepts_only_the_observed_private_docker0_address(self):
        from local_git_service import docker_bridge_listener
        good = subprocess.CompletedProcess([], 0, stdout=json.dumps([
            {"addr_info": [{"family": "inet", "local": "172.17.0.1"}]}
        ]), stderr="")
        with mock.patch("local_git_service.platform.system", return_value="Linux"), \
                mock.patch("local_git_service.shutil.which", return_value="/usr/sbin/ip"), \
                mock.patch("local_git_service.subprocess.run", return_value=good) as command:
            self.assertEqual(docker_bridge_listener("172.17.0.1"), "172.17.0.1")
            self.assertEqual(command.call_args.args[0][-5:], ["-j", "address", "show", "dev", "docker0"])
            self.assertEqual(command.call_args.kwargs["timeout"], 5)


class AuthenticatedGitTests(unittest.TestCase):
    def setUp(self):
        named = os.environ.get("AGENT_GUARD_TEST_CLI")
        if not named or not Path(named).is_file():
            # Required suite, never a misleading skip when the CLI is absent.
            self.fail("set AGENT_GUARD_TEST_CLI to the newly built executable")
        self.cli = Path(named).resolve()
        self.temp = tempfile.TemporaryDirectory(prefix="agent-guard-auth-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.service = LocalGitService(self.root)
        self.addCleanup(self.service.close)
        self.work = self.root / "work"
        self.work.mkdir()
        run_git(self.work, "init", "-b", "main")
        run_git(self.work, "config", "user.name", "Local Fixture")
        run_git(self.work, "config", "user.email", "fixture@example.invalid")
        (self.work / "fixture.txt").write_text("harmless local fixture\n")
        run_git(self.work, "add", "fixture.txt")
        run_git(self.work, "commit", "-m", "fixture")
        self.oid = run_git(self.work, "rev-parse", "HEAD").stdout.decode().strip()
        run_git(self.work, "remote", "add", "origin", self.service.url)
        self.config = self.service.trusted_config(self.root / "trusted.gitconfig")
        self.policy = self.root / "policy.yaml"
        self.policy.write_text(
            "version: 1\ndefault_mode: workspace_write\ntools:\n  bash:\n"
            "    ask:\n      - prefix: 'git push'\naudit:\n  enabled: false\n"
            "anomaly:\n  enabled: false\n"
        )
        self.receipt = self.root / "receipt.json"

    def broker(self, answer, config=None):
        return subprocess.run(
            [str(self.cli), "push", "--repo", str(self.work),
             "--policy", str(self.policy), "--git-config", str(config or self.config),
             "--remote", "origin", "--branch", "main", "--grants", str(self.root / "grants"),
             "--receipt", str(self.receipt)],
            input=answer, capture_output=True, timeout=30, env=git_env(), cwd=self.root,
        )

    def test_reachable_tls_service_refuses_unauthenticated_mutation(self):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.service.port, timeout=5,
            context=ssl.create_default_context(cafile=self.service.cert),
        )
        self.addCleanup(connection.close)
        connection.request("GET", "/repo.git/info/refs?service=git-receive-pack")
        self.assertEqual(connection.getresponse().status, 401)
        result = run_git(
            self.work, "-c", f"http.sslCAInfo={self.service.cert}",
            "push", "origin", "main", check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(self.service.tip())
        self.assertTrue(self.service.requests)
        self.assertFalse(any(auth for _, _, auth in self.service.requests))

    def test_approved_host_push_matches_independent_ref_and_receipt(self):
        result = self.broker(b"y\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.service.tip(), self.oid)
        record = json.loads(self.receipt.read_text())
        self.assertEqual(record["transaction"]["remote_url"], self.service.url)
        self.assertEqual(record["transaction"]["local_oid"], self.oid)
        self.assertTrue(record["grant_id"])
        self.assertEqual(record["attempt"]["outcome"], "pushed")
        self.assertEqual(record["witness"]["kind"], "unsigned")
        self.assertIn(self.service.url, result.stdout.decode())
        self.assertTrue(any(auth for _, _, auth in self.service.requests))

    def test_cancel_and_eof_do_not_mutate_or_create_execution_receipt(self):
        for answer in (b"n\n", b""):
            result = self.broker(answer)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(self.service.tip())
            self.assertFalse(self.receipt.exists())
        self.assertTrue(any(auth for _, _, auth in self.service.requests))
        self.assertFalse(any(path.endswith("git-receive-pack") for _, path, _ in self.service.requests))

    def test_out_of_scope_destination_is_refused_before_connection(self):
        other_config = self.root / "out-of-scope.gitconfig"
        other_config.write_text(
            '[credential "https://approved.invalid/repo.git"]\nhelper = fixture-never-run\n'
        )
        other_config.chmod(0o600)
        result = self.broker(b"y\n", config=other_config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted authentication scope", result.stderr.decode())
        self.assertEqual(self.service.requests, [])
        self.assertIsNone(self.service.tip())
        self.assertFalse(self.receipt.exists())

    def test_incomplete_tls_handshake_cannot_hold_fixture_shutdown(self):
        connection = socket.create_connection(("127.0.0.1", self.service.port), timeout=3)
        self.addCleanup(connection.close)
        connection.sendall(b"\x16")  # A partial local handshake, no HTTP request.
        self.assertTrue(self.service.handshake_started.wait(2))
        start = time.monotonic()
        self.service.close()
        self.assertLess(time.monotonic() - start, 3)
        self.assertIsNone(self.service.tip())

    def test_observer_failure_is_not_recorded_as_an_absent_ref(self):
        failure = subprocess.CompletedProcess(["git"], 128, stdout=b"", stderr=b"fixture failure")
        with mock.patch("local_git_service.run_git", return_value=failure):
            with self.assertRaises(subprocess.CalledProcessError):
                self.service.tip()


if __name__ == "__main__":
    unittest.main()
