import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts" / "guard-hook-plugin.sh"
APPROVE = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "",
    }
}


class GuardHookPluginTests(unittest.TestCase):
    def fixture(self, metadata="valid", binary_mode="exact"):
        context = tempfile.TemporaryDirectory()
        root = Path(context.__enter__())
        self.addCleanup(context.__exit__, None, None, None)

        (root / "presets").mkdir()
        (root / "presets/coding-agent-outbound.yaml").write_text(
            "version: '1'\ndefault_mode: workspace_write\n",
            encoding="utf-8",
        )
        if metadata != "missing":
            (root / ".claude-plugin").mkdir()
            content = "{not json" if metadata == "invalid" else json.dumps(
                {"name": "agent-guard", "version": "0.2.5"}
            )
            (root / ".claude-plugin/plugin.json").write_text(content, encoding="utf-8")

        bin_dir = root / "fake-bin"
        bin_dir.mkdir()
        log = root / "calls.log"
        fake = bin_dir / "guard-hook"
        fake.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$FAKE_GUARD_LOG\"\n"
            "if [ \"$1\" = \"--version\" ]; then\n"
            "  case \"$FAKE_GUARD_MODE\" in\n"
            "    exact) echo 'guard-hook 0.2.5'; exit 0 ;;\n"
            "    stale) echo 'guard-hook 0.2.4'; exit 0 ;;\n"
            "    failure) exit 17 ;;\n"
            "  esac\n"
            "fi\n"
            "echo '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"checked\"}}'\n",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

        env = os.environ.copy()
        env.update(
            {
                "CLAUDE_PLUGIN_ROOT": str(root),
                "FAKE_GUARD_LOG": str(log),
                "FAKE_GUARD_MODE": binary_mode,
                "HOME": str(root / "home"),
                "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            }
        )
        return root, log, env

    def run_wrapper(self, metadata="valid", binary_mode="exact"):
        _, log, env = self.fixture(metadata, binary_mode)
        result = subprocess.run(
            ["bash", str(WRAPPER)],
            input="{}\n",
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return result, calls

    def assert_approved(self, result):
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), APPROVE)

    def test_matching_version_runs_check(self):
        result, calls = self.run_wrapper()

        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(calls[0], "--version")
        self.assertTrue(calls[1].startswith("check --policy "))

    def test_stale_binary_fails_open_without_check(self):
        result, calls = self.run_wrapper(binary_mode="stale")

        self.assert_approved(result)
        self.assertEqual(calls, ["--version"])
        self.assertIn("version mismatch", result.stderr)

    def test_version_probe_failure_fails_open_without_check(self):
        result, calls = self.run_wrapper(binary_mode="failure")

        self.assert_approved(result)
        self.assertEqual(calls, ["--version"])
        self.assertIn("--version exited 17", result.stderr)

    def test_missing_or_invalid_metadata_never_invokes_binary(self):
        for metadata in ("missing", "invalid"):
            with self.subTest(metadata=metadata):
                result, calls = self.run_wrapper(metadata=metadata)
                self.assert_approved(result)
                self.assertEqual(calls, [])
                self.assertIn("version metadata missing or invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()
