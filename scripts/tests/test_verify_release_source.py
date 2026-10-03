from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "release"
    / "verify_release_source.py"
)
SPEC = importlib.util.spec_from_file_location("verify_release_source", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class ReleaseSourceTests(unittest.TestCase):
    def make_repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        temporary = tempfile.TemporaryDirectory()
        repo = Path(temporary.name)
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "Release Test")
        git(repo, "config", "user.email", "release@example.invalid")
        (repo / "file.txt").write_text("one\n", encoding="utf-8")
        git(repo, "add", "file.txt")
        git(repo, "commit", "-qm", "one")
        commit = git(repo, "rev-parse", "HEAD")
        git(repo, "update-ref", "refs/remotes/origin/main", commit)
        return temporary, repo, commit

    def test_tag_commit_equal_to_origin_main_is_accepted(self) -> None:
        temporary, repo, commit = self.make_repo()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(MODULE.verify_git_source(repo, commit), commit)

    def test_tag_commit_different_from_origin_main_is_rejected(self) -> None:
        temporary, repo, first = self.make_repo()
        self.addCleanup(temporary.cleanup)
        (repo / "file.txt").write_text("two\n", encoding="utf-8")
        git(repo, "add", "file.txt")
        git(repo, "commit", "-qm", "two")
        second = git(repo, "rev-parse", "HEAD")
        self.assertNotEqual(first, second)
        with self.assertRaisesRegex(MODULE.VerificationError, "not current origin/main"):
            MODULE.verify_git_source(repo, second)

    def test_successful_same_sha_main_push_is_accepted(self) -> None:
        MODULE.require_successful_main_ci(
            [
                {
                    "head_sha": "abc",
                    "head_branch": "main",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
            "abc",
        )

    def test_wrong_sha_failure_or_missing_run_is_rejected(self) -> None:
        wrong_sha = [
            {
                "head_sha": "other",
                "head_branch": "main",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
            }
        ]
        with self.assertRaisesRegex(MODULE.VerificationError, "no completed"):
            MODULE.require_successful_main_ci(wrong_sha, "abc")

        failed = [
            {
                "head_sha": "abc",
                "head_branch": "main",
                "event": "push",
                "status": "completed",
                "conclusion": "failure",
            }
        ]
        with self.assertRaisesRegex(MODULE.VerificationError, "not successful"):
            MODULE.require_successful_main_ci(failed, "abc")

        with self.assertRaisesRegex(MODULE.VerificationError, "no completed"):
            MODULE.require_successful_main_ci([], "abc")

    def test_malformed_api_response_is_rejected(self) -> None:
        for payload in [b"not-json", json.dumps({"runs": []}).encode(), b'{"workflow_runs":[1]}']:
            with self.subTest(payload=payload):
                with self.assertRaises(MODULE.VerificationError):
                    MODULE.parse_workflow_runs(payload)


if __name__ == "__main__":
    unittest.main()
