from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_workflow_pins.py"
SPEC = importlib.util.spec_from_file_location("check_workflow_pins", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WorkflowPinTests(unittest.TestCase):
    def check(self, action: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "ci.yml").write_text(
                f"jobs:\n  test:\n    steps:\n      - uses: {action}\n",
                encoding="utf-8",
            )
            return MODULE.find_unpinned(root)

    def test_full_commit_sha_is_accepted(self) -> None:
        self.assertEqual(
            self.check(
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
            ),
            [],
        )

    def test_local_action_is_accepted(self) -> None:
        self.assertEqual(self.check("./.github/actions/local"), [])

    def test_mutable_major_tag_is_rejected(self) -> None:
        self.assertEqual(len(self.check("actions/checkout@v4")), 1)

    def test_short_and_overlong_hashes_are_rejected(self) -> None:
        self.assertEqual(len(self.check(f"actions/checkout@{'a' * 39}")), 1)
        self.assertEqual(len(self.check(f"actions/checkout@{'a' * 41}")), 1)


if __name__ == "__main__":
    unittest.main()
