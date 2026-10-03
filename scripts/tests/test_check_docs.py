import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_docs", ROOT / "scripts/check_docs.py")
CHECK_DOCS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CHECK_DOCS)


class PluginMetadataDocumentationTests(unittest.TestCase):
    def test_current_plugin_metadata_has_no_signed_receipt_claim(self):
        with contextlib.redirect_stdout(io.StringIO()):
            errors = CHECK_DOCS.check_plugin_metadata(ROOT)
        self.assertEqual(errors, 0)

    def test_signed_receipt_claim_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / ".claude-plugin"
            metadata.mkdir()
            (metadata / "plugin.json").write_text(
                json.dumps({"description": "Gate calls with Ed25519-signed audit receipts."}),
                encoding="utf-8",
            )
            (metadata / "marketplace.json").write_text(
                json.dumps({"metadata": {"description": "Decision-only policy hook."}}),
                encoding="utf-8",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                errors = CHECK_DOCS.check_plugin_metadata(root)

            self.assertEqual(errors, 1)
            self.assertIn("Misleading signed-receipt claim", output.getvalue())


if __name__ == "__main__":
    unittest.main()
