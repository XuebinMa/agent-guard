import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
AUDIT_SCRIPT = ROOT / ".claude" / "workflows" / "weekly-deep-audit.sh"


class WeeklyDeepAuditTests(unittest.TestCase):
    def make_repo(self, claude_exit: int) -> tuple[Path, dict[str, str]]:
        repo = Path(self.addCleanupContext(tempfile.TemporaryDirectory()))
        subprocess.run(["git", "init", "-q", str(repo)], check=True)

        workflow_dir = repo / ".claude" / "workflows"
        workflow_dir.mkdir(parents=True)
        shutil.copy2(AUDIT_SCRIPT, workflow_dir / AUDIT_SCRIPT.name)

        bin_dir = repo / "bin"
        bin_dir.mkdir()
        claude = bin_dir / "claude"
        claude.write_text(
            "#!/bin/sh\n"
            "cat >/dev/null\n"
            "echo '_no findings_'\n"
            f"echo 'fake stderr' >&2\nexit {claude_exit}\n",
            encoding="utf-8",
        )
        claude.chmod(claude.stat().st_mode | stat.S_IXUSR)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
        return repo, env

    def addCleanupContext(self, context):
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def run_audit(self, claude_exit: int) -> tuple[subprocess.CompletedProcess[str], str]:
        repo, env = self.make_repo(claude_exit)
        result = subprocess.run(
            [
                "bash",
                str(repo / ".claude" / "workflows" / AUDIT_SCRIPT.name),
                "--agent",
                "silent-failure",
            ],
            cwd=repo,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        reports = list((repo / "docs" / "audits").glob("*.md"))
        self.assertEqual(len(reports), 1)
        return result, reports[0].read_text(encoding="utf-8")

    def test_agent_failure_propagates_nonzero_status(self):
        result, report = self.run_audit(42)

        self.assertEqual(result.returncode, 1)
        self.assertIn("silent-failure returned non-zero", result.stderr)
        self.assertIn("| silent-failure-hunter | SDK + validators + sandbox | fail |", report)
        self.assertIn("Agent run returned non-zero", report)
        self.assertIn("fake stderr", report)

    def test_successful_agent_returns_zero(self):
        result, report = self.run_audit(0)

        self.assertEqual(result.returncode, 0)
        self.assertIn("| silent-failure-hunter | SDK + validators + sandbox | ok |", report)
        self.assertIn("_no findings_", report)


if __name__ == "__main__":
    unittest.main()
