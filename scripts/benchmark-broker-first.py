#!/usr/bin/env python3
"""Bounded synthetic CLI/snapshot-cost measurement, with local file remotes only.

No Cargo, network service, user repository, credential or deployment is used.
Stdout is a JSON report; diagnostics go to stderr. A sampled high-water mark
is explicitly not a measured peak or a measurement of copy time alone.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time


MIB = 1024 * 1024
SEED = 20261006
MAX_SIZE_MIB = 128
MAX_ITERATIONS = 3
MAX_RUN_SECONDS = 600
ROOT = Path(__file__).resolve().parents[1]


def sizes_argument(text):
    try:
        sizes = [int(value) for value in text.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("sizes must be three comma-separated integers") from error
    if len(sizes) != 3 or len(set(sizes)) != 3 or sizes != sorted(sizes):
        raise argparse.ArgumentTypeError("choose exactly three distinct increasing sizes")
    if not all(1 <= size <= MAX_SIZE_MIB for size in sizes):
        raise argparse.ArgumentTypeError(f"each size must be between 1 and {MAX_SIZE_MIB} MiB")
    return sizes


def bounded_integer(low, high):
    def parse(text):
        try:
            value = int(text)
        except ValueError as error:
            raise argparse.ArgumentTypeError("must be an integer") from error
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value
    return parse


def environment(home, scratch):
    # Explicit test environment: no developer Git/SSH/proxy/helper/token state.
    return {
        "PATH": os.defpath, "HOME": str(home), "TMPDIR": str(scratch),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_AUTHOR_DATE": "2026-10-06T00:00:00+0000",
        "GIT_COMMITTER_DATE": "2026-10-06T00:00:00+0000", "LC_ALL": "C",
    }


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def footprint(root):
    """Regular-file bytes only; races with normal tempfile deletion are expected."""
    logical = allocated = 0
    for directory, _, files in os.walk(root, followlinks=False):
        for name in files:
            try:
                info = (Path(directory) / name).lstat()
            except (FileNotFoundError, NotADirectoryError):
                continue
            if stat.S_ISREG(info.st_mode):
                logical += info.st_size
                allocated += getattr(info, "st_blocks", 0) * 512
    return {"logical_file_bytes": logical, "allocated_file_bytes_estimate": allocated}


class Sampler:
    def __init__(self, root, interval):
        self.root, self.interval = root, interval
        self.maximum = footprint(root)
        self.samples = 0
        self.errors = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            try:
                observed = footprint(self.root)
                for key in self.maximum:
                    self.maximum[key] = max(self.maximum[key], observed[key])
                self.samples += 1
            except OSError as error:
                self.errors.append(type(error).__name__)
            self.stop.wait(self.interval)

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("temporary-footprint sampler did not stop")
        return {"sampled_maximum": self.maximum, "samples": self.samples,
                "sampling_errors": self.errors, "is_true_peak": False}


class Runner:
    def __init__(self, env, timeout):
        self.env, self.timeout = env, timeout
        self.deadline = time.monotonic() + MAX_RUN_SECONDS

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("benchmark exceeded its ten-minute run deadline")
        return min(left, self.timeout)

    def run(self, argv, cwd, *, input_bytes=b"", check=True):
        timeout = self.remaining()
        child = subprocess.Popen(
            [str(value) for value in argv], cwd=cwd, env=self.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = child.communicate(input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            # Only the process group created for this owned test invocation.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=5)
            raise TimeoutError("local benchmark subprocess exceeded its deadline")
        result = subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
        if check and result.returncode:
            raise RuntimeError(f"{Path(str(argv[0])).name} failed: {stderr.decode(errors='replace')}")
        return result

    def git(self, cwd, *args):
        return self.run(["git", "-c", f"core.hooksPath={os.devnull}", *args], cwd)


def source_state(runner):
    sha = runner.git(ROOT, "rev-parse", "HEAD").stdout.decode().strip()
    status = runner.git(ROOT, "status", "--porcelain=v1", "-z").stdout
    diff = runner.git(ROOT, "diff", "--binary", "HEAD").stdout
    return {"head": sha, "dirty": bool(status),
            "status_porcelain": status.decode(errors="replace").split("\0"),
            "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
            "untracked_contents_in_diff_hash": False}


def make_payload(path, byte_count, runner):
    generator = random.Random(SEED)
    digest = hashlib.sha256()
    with path.open("xb") as stream:
        left = byte_count
        while left:
            runner.remaining()
            chunk = generator.randbytes(min(MIB, left))
            stream.write(chunk)
            digest.update(chunk)
            left -= len(chunk)
    return digest.hexdigest()


def cli_arguments(cli, repo, policy, config, grants, receipt):
    return [cli, "push", "--repo", repo, "--policy", policy, "--git-config", config,
            "--remote", "origin", "--branch", "main", "--grants", grants,
            "--receipt", receipt, "--allow-local-file-remote"]


def measure(runner, argv, cwd, scratch, answer, interval):
    sampler = Sampler(scratch, interval)
    sampler.thread.start()
    started = time.perf_counter()
    try:
        result = runner.run(argv, cwd, input_bytes=answer, check=False)
        elapsed = time.perf_counter() - started
    finally:
        observed = sampler.finish()
    return result, {"wall_seconds": elapsed, **observed}


def one_size(root, size, args, runner):
    case = root / f"size-{size}"
    case.mkdir()
    repo = case / "work"
    runner.git(case, "init", "--object-format=sha1", "-b", "main", repo)
    runner.git(repo, "config", "user.name", "Synthetic Benchmark")
    runner.git(repo, "config", "user.email", "benchmark@example.invalid")
    digest = make_payload(repo / "payload.bin", size * MIB, runner)
    runner.git(repo, "add", "payload.bin")
    runner.git(repo, "-c", "commit.gpgsign=false", "commit", "-m", "Synthetic snapshot cost")
    runner.git(repo, "repack", "-ad")
    runner.git(repo, "prune-packed")
    oid = runner.git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    objects = footprint(repo / ".git/objects")
    trials = []
    for iteration in range(1, args.iterations + 1):
        with tempfile.TemporaryDirectory(prefix="trial-", dir=case) as trial_path:
            trial = Path(trial_path)
            remote = trial / "remote.git"
            scratch = trial / "broker-scratch"
            scratch.mkdir()
            runner.git(trial, "init", "--bare", "--object-format=sha1", "-b", "main", remote)
            if iteration == 1:
                runner.git(repo, "remote", "add", "origin", remote)
            else:
                runner.git(repo, "remote", "set-url", "origin", remote)
            receipt = trial / "receipt.json"
            argv = cli_arguments(args.cli, repo, root / "policy.yaml", root / "broker.gitconfig",
                                 trial / "grants", receipt)
            previous_env = runner.env
            runner.env = environment(root / "home", scratch)
            try:
                # macOS /usr/bin/git's toolchain shim may retain xcrun_db here.
                # Establish/report that baseline; never call it a broker leak
                # or silently omit it from sampled temporary-file accounting.
                runner.git(trial, "--version")
                baseline_names = sorted(path.name for path in scratch.iterdir())
                baseline = footprint(scratch)
                refused, preview = measure(runner, argv, trial, scratch, b"n\n", args.sample_ms / 1000)
                if refused.returncode != 1 or receipt.exists() or b"Not pushed." not in refused.stdout:
                    raise RuntimeError("preview cancellation did not stop before execution")
                if runner.git(remote, "for-each-ref", "--format=%(refname)").stdout.strip():
                    raise RuntimeError("preview cancellation unexpectedly changed the local remote")
                pushed, execution = measure(runner, argv, trial, scratch, b"y\n", args.sample_ms / 1000)
                if pushed.returncode:
                    raise RuntimeError(f"local broker push failed: {pushed.stderr.decode(errors='replace')}")
                actual = runner.git(remote, "rev-parse", "--verify", "refs/heads/main").stdout.decode().strip()
                record = json.loads(receipt.read_text())
                tx = record.get("transaction") or {}
                if (actual != oid or tx.get("local_oid") != oid or tx.get("remote_url") != str(remote)
                        or record.get("attempt", {}).get("outcome") != "pushed"
                        or record.get("witness", {}).get("kind") != "unsigned" or not record.get("grant_id")):
                    raise RuntimeError("independent local ref and broker receipt disagree")
                leftovers = sorted(path.name for path in scratch.iterdir())
                if leftovers != baseline_names:
                    raise RuntimeError(f"temporary file set changed after normal completion: {leftovers}")
                remaining = footprint(scratch)
            finally:
                runner.env = previous_env
            trials.append({"iteration": iteration, "preview_cancel": preview,
                           "approve_and_push_including_preview": execution,
                           "git_toolchain_baseline": {"file_names": baseline_names, **baseline},
                           "temporary_files_after_cli": {"file_names": leftovers, **remaining},
                           "independent_ref_matches_receipt": True})
    return {"payload_mib": size, "payload_bytes": size * MIB, "payload_sha256": digest,
            "storage": "one repacked commit/tree/blob; synthetic pseudo-random bytes",
            "primary_objects": objects, "local_oid": oid, "trials": trials}


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path, help="freshly built existing agent-guard binary")
    parser.add_argument("--sizes-mib", type=sizes_argument, default=[1, 8, 32])
    parser.add_argument("--iterations", type=bounded_integer(1, MAX_ITERATIONS), default=2)
    parser.add_argument("--sample-ms", type=bounded_integer(5, 100), default=10)
    parser.add_argument("--timeout-seconds", type=bounded_integer(5, 120), default=60)
    parser.add_argument("--filesystem", default="not supplied", help="operator-verified filesystem type/conditions, no paths or secrets")
    parser.add_argument("--hardware", default="not supplied", help="operator-verified model/memory description, no serial number")
    parser.add_argument("--temp-parent", type=Path, help="existing writable local scratch filesystem; not a user repository")
    return parser.parse_args(argv)


def main():
    args = parse_arguments()
    if os.name != "posix":
        raise RuntimeError("this benchmark currently supports Unix test hosts only")
    args.cli = args.cli.resolve(strict=True)
    if not args.cli.is_file() or not os.access(args.cli, os.X_OK):
        raise RuntimeError("--cli must be an executable ordinary file")
    if not shutil.which("git", path=os.defpath):
        raise RuntimeError("Git is required on the controlled operating-system PATH")
    with tempfile.TemporaryDirectory(prefix="agent-guard-snapshot-benchmark-", dir=args.temp_parent) as path:
        root = Path(path).resolve()
        (root / "home").mkdir()
        (root / "scratch").mkdir()
        (root / "broker.gitconfig").touch(mode=0o600)
        (root / "policy.yaml").write_text(
            "version: 1\ndefault_mode: workspace_write\ntools:\n  bash:\n"
            "    ask:\n      - prefix: 'git push'\naudit:\n  enabled: false\n"
            "anomaly:\n  enabled: false\n", encoding="utf-8",
        )
        required = sum(args.sizes_mib) * MIB * 6 + 64 * MIB
        if shutil.disk_usage(root).free < required:
            raise RuntimeError(f"not enough scratch space for conservative {required}-byte test budget")
        runner = Runner(environment(root / "home", root / "scratch"), args.timeout_seconds)
        binary_digest = file_hash(args.cli)
        before = source_state(runner)
        info = os.statvfs(root)
        report = {
            "schema": 1, "at_utc": datetime.now(timezone.utc).isoformat(),
            "source_before": before, "binary_sha256": binary_digest,
            "benchmark_script_sha256": file_hash(Path(__file__)),
            "cli_version": runner.run([args.cli, "--version"], root).stdout.decode().strip(),
            "git_version": runner.git(root, "--version").stdout.decode().strip(),
            "host": {"os": platform.platform(), "machine": platform.machine(),
                     "processor": platform.processor(), "logical_cpu_count": os.cpu_count(),
                     "hardware_description": args.hardware,
                     "python": platform.python_version(), "filesystem_description": args.filesystem,
                     "scratch_device": root.stat().st_dev, "filesystem_block_bytes": info.f_frsize,
                     "free_bytes_before": info.f_bavail * info.f_frsize},
            "method": {"seed": SEED, "iterations": args.iterations, "sample_ms": args.sample_ms,
                       "subprocess_timeout_seconds": args.timeout_seconds,
                       "whole_run_deadline_seconds": MAX_RUN_SECONDS,
                       "cache_condition": "not flushed; generated/repacked just before measurement; system Git --version prewarms toolchain cache in each trial TMPDIR; no cold-cache claim",
                       "timing_scope": "whole CLI wall time, including validation/fsck/preview/local Git transport; not pure copy time",
                       "footprint_scope": "observed regular-file maximum in per-trial broker TMPDIR only; sampling can miss short-lived files; no directory metadata or complete process/RSS peak",
                       "limitations": "one synthetic repacked blob/commit/tree; file transport, no authentication/TLS/container proof; sampler adds I/O; do not extrapolate to production"},
            "cases": [],
        }
        for size in args.sizes_mib:
            print(f"measuring synthetic {size} MiB case", file=sys.stderr, flush=True)
            report["cases"].append(one_size(root, size, args, runner))
        report["source_after"] = source_state(runner)
        report["source_changed_during_run"] = before != report["source_after"]
        if binary_digest != file_hash(args.cli):
            raise RuntimeError("CLI binary changed during measurement; discard this run")
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        sys.exit(1)
