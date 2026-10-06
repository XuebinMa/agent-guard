"""Benchmark method tests, not authentication or container-isolation evidence."""

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "benchmark-broker-first.py"
SPEC = importlib.util.spec_from_file_location("broker_first_benchmark", SOURCE)
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agent-guard-benchmark-method-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_three_sizes_are_bounded_distinct_and_increasing(self):
        self.assertEqual(benchmark.sizes_argument("1,8,32"), [1, 8, 32])
        self.assertEqual(benchmark.sizes_argument("1,64,128"), [1, 64, 128])
        for text in ["", "1,8", "1,8,32,64", "0,8,32", "1,8,129", "1,1,8", "8,1,32", "1,x,32"]:
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError):
                benchmark.sizes_argument(text)

    def test_default_method_and_scalar_bounds(self):
        args = benchmark.parse_arguments(["--cli", "/fixture/agent-guard"])
        self.assertEqual(args.sizes_mib, [1, 8, 32])
        self.assertEqual(args.iterations, 2)
        self.assertEqual(args.sample_ms, 10)
        for text in ["0", "4", "no"]:
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError):
                benchmark.bounded_integer(1, 3)(text)
        self.assertEqual(benchmark.bounded_integer(1, 3)("3"), 3)

    def test_test_environment_does_not_forward_host_credentials(self):
        with mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": "/fixture/socket", "GITHUB_TOKEN": "public-fixture"}):
            env = benchmark.environment(self.root / "home", self.root / "scratch")
        for name in ["SSH_AUTH_SOCK", "GITHUB_TOKEN", "GH_TOKEN", "HTTP_PROXY", "GIT_CONFIG_COUNT", "LD_PRELOAD"]:
            self.assertNotIn(name, env)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["HOME"], str(self.root / "home"))

    def test_payload_is_repeatable_and_refuses_overwrite(self):
        runner = mock.Mock()
        first, second = self.root / "one.bin", self.root / "two.bin"
        digest = benchmark.make_payload(first, 4096, runner)
        self.assertEqual(benchmark.make_payload(second, 4096, runner), digest)
        self.assertEqual(first.stat().st_size, 4096)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(benchmark.file_hash(first), digest)
        with self.assertRaises(FileExistsError):
            benchmark.make_payload(first, 4096, runner)

    def test_footprint_is_regular_file_accounting_not_a_true_peak(self):
        target = self.root / "regular"
        target.write_bytes(b"public-data")
        (self.root / "link").symlink_to(target)
        counts = benchmark.footprint(self.root)
        self.assertEqual(counts["logical_file_bytes"], len(b"public-data"))
        self.assertEqual(counts["allocated_file_bytes_estimate"], target.stat().st_blocks * 512)
        sampler = benchmark.Sampler(self.root, 0.01)
        sampler.thread.start()
        observed = sampler.finish()
        self.assertFalse(observed["is_true_peak"])
        self.assertEqual(observed["sampled_maximum"], counts)
        self.assertEqual(observed["sampling_errors"], [])

    def test_only_benchmark_enables_the_local_test_transport(self):
        args = benchmark.cli_arguments("/fixture/agent-guard", "repo", "policy", "config", "grants", "receipt")
        self.assertIn("--allow-local-file-remote", args)
        self.assertNotIn("--yes", args)
        self.assertIn("--git-config", args)
        self.assertIn("--receipt", args)

    def test_source_metadata_does_not_claim_untracked_content_is_hashed(self):
        runner = mock.Mock()
        status, diff = b"?? fixture\0", b"tracked public fixture diff"
        runner.git.side_effect = [
            subprocess.CompletedProcess([], 0, b"a" * 40 + b"\n"),
            subprocess.CompletedProcess([], 0, status),
            subprocess.CompletedProcess([], 0, diff),
        ]
        recorded = benchmark.source_state(runner)
        self.assertTrue(recorded["dirty"])
        self.assertEqual(recorded["tracked_diff_sha256"], hashlib.sha256(diff).hexdigest())
        self.assertFalse(recorded["untracked_contents_in_diff_hash"])

    @unittest.skipUnless(os.name == "posix", "benchmark explicitly supports Unix test hosts")
    def test_owned_subprocess_times_out_without_a_shell(self):
        runner = benchmark.Runner(benchmark.environment(self.root, self.root), 0.05)
        with self.assertRaises(TimeoutError):
            runner.run([sys.executable, "-c", "import time; time.sleep(30)"], self.root)
        runner.deadline = 0
        with self.assertRaises(TimeoutError):
            runner.remaining()


if __name__ == "__main__":
    unittest.main()
