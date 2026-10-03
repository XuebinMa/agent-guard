import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "version_markers.py"

FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "pyproject.toml",
    "README.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "docs/README.md",
    "docs/guides/operations/claude-code-plugin.md",
    "crates/agent-guard-node/package.json",
    "crates/agent-guard-node/package-lock.json",
    "crates/agent-guard-python/pyproject.toml",
    "crates/agent-guard-python/README.md",
    ".claude-plugin/plugin.json",
    ".claude-plugin/marketplace.json",
    "packages/agent-guard-plugin/package.json",
)


class VersionMarkerTests(unittest.TestCase):
    def fixture(self) -> Path:
        context = tempfile.TemporaryDirectory()
        root = Path(context.__enter__())
        self.addCleanup(context.__exit__, None, None, None)

        for relative in FILES:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        for manifest in (ROOT / "crates").glob("*/Cargo.toml"):
            destination = root / manifest.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest, destination)
        return root

    def run_script(self, root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments, "--root", str(root)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_bump_changes_source_markers_but_preserves_published_release(self):
        root = self.fixture()

        result = self.run_script(root, "bump", "9.8.7-rc.1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("published release remains 0.2.6", result.stdout)
        check = self.run_script(root, "check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("source 9.8.7-rc.1, published release 0.2.6", check.stdout)

        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn("Source version**: `v9.8.7-rc.1`", readme)
        self.assertIn("releases/tag/v0.2.6", readme)
        python_readme = (root / "crates/agent-guard-python/README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("latest published package is `0.2.6`", python_readme)
        self.assertIn("current `9.8.7-rc.1` source", python_readme)

    def test_detects_secondary_node_lock_version_drift(self):
        root = self.fixture()
        path = root / "crates/agent-guard-node/package-lock.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["packages"][""]["version"] = "0.0.0"
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

        result = self.run_script(root, "check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node package-lock.json root package", result.stderr)

    def test_detects_published_release_drift_independently(self):
        root = self.fixture()
        path = root / "docs/README.md"
        text = path.read_text(encoding="utf-8")
        text = text.replace("releases/tag/v0.2.6", "releases/tag/v0.2.5", 1)
        text = text.replace("[`v0.2.6`](https://github.com", "[`v0.2.5`](https://github.com", 1)
        path.write_text(text, encoding="utf-8")

        result = self.run_script(root, "check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docs/README published release", result.stderr)

    def test_requires_exact_local_dependency_pins(self):
        root = self.fixture()
        path = root / "crates/agent-guard-cli/Cargo.toml"
        text = path.read_text(encoding="utf-8").replace(
            'version = "=0.2.6"', 'version = "0.2.6"', 1
        )
        path.write_text(text, encoding="utf-8")

        result = self.run_script(root, "check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not exact-pinned", result.stderr)

    def test_failed_bump_rolls_back_earlier_file_changes(self):
        root = self.fixture()
        lock_path = root / "Cargo.lock"
        lock_text = lock_path.read_text(encoding="utf-8").replace(
            'name = "agent-guard-broker"\nversion = "0.2.6"',
            'name = "agent-guard-broker"\nsource = "registry+https://example.invalid/index"\nversion = "0.2.6"',
            1,
        )
        lock_path.write_text(lock_text, encoding="utf-8")
        cargo_before = (root / "Cargo.toml").read_bytes()

        result = self.run_script(root, "bump", "9.8.7")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo.lock package agent-guard-broker", result.stderr)
        self.assertEqual((root / "Cargo.toml").read_bytes(), cargo_before)


if __name__ == "__main__":
    unittest.main()
