import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
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
    def source_version(self, root: Path) -> str:
        document = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        return document["workspace"]["package"]["version"]

    def published_version(self, root: Path) -> str:
        text = (root / "README.md").read_text(encoding="utf-8")
        match = re.search(r"Latest published release\*\*:\s*\[`v([^`]+)`", text)
        self.assertIsNotNone(match, "fixture must name its actual published release")
        return match.group(1)

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
        published = self.published_version(root)

        result = self.run_script(root, "bump", "9.8.7-rc.1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"published release remains {published}", result.stdout)
        check = self.run_script(root, "check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn(f"source 9.8.7-rc.1, published release {published}", check.stdout)

        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn("Source version**: `v9.8.7-rc.1`", readme)
        self.assertIn(f"releases/tag/v{published}", readme)
        python_readme = (root / "crates/agent-guard-python/README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"latest published package is `{published}`", python_readme)
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
        published = self.published_version(root)
        path = root / "docs/README.md"
        text = path.read_text(encoding="utf-8")
        changed = text.replace(f"releases/tag/v{published}", "releases/tag/v0.0.0", 1)
        changed = changed.replace(f"[`v{published}`](https://github.com", "[`v0.0.0`](https://github.com", 1)
        self.assertNotEqual(changed, text, "negative control must actually change the fixture")
        path.write_text(changed, encoding="utf-8")

        result = self.run_script(root, "check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docs/README published release", result.stderr)

    def test_requires_exact_local_dependency_pins(self):
        root = self.fixture()
        source = self.source_version(root)
        path = root / "crates/agent-guard-cli/Cargo.toml"
        text = path.read_text(encoding="utf-8")
        changed = text.replace(f'version = "={source}"', f'version = "{source}"', 1)
        self.assertNotEqual(changed, text, "negative control must remove a real exact pin")
        path.write_text(changed, encoding="utf-8")

        result = self.run_script(root, "check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not exact-pinned", result.stderr)

    def test_failed_bump_rolls_back_earlier_file_changes(self):
        root = self.fixture()
        source = self.source_version(root)
        lock_path = root / "Cargo.lock"
        lock_text = lock_path.read_text(encoding="utf-8")
        changed = lock_text.replace(
            f'name = "agent-guard-broker"\nversion = "{source}"',
            f'name = "agent-guard-broker"\nsource = "registry+https://example.invalid/index"\nversion = "{source}"',
            1,
        )
        self.assertNotEqual(changed, lock_text, "negative control must alter the real broker entry")
        lock_path.write_text(changed, encoding="utf-8")
        paths = {root / relative for relative in FILES} | set((root / "crates").glob("*/Cargo.toml"))
        originals = {path: path.read_bytes() for path in paths}

        result = self.run_script(root, "bump", "9.8.7")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo.lock package agent-guard-broker", result.stderr)
        for path, original in originals.items():
            self.assertEqual(path.read_bytes(), original, f"partial rollback at {path.relative_to(root)}")


if __name__ == "__main__":
    unittest.main()
