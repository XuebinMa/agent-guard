import importlib.util
import json
from pathlib import Path

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verifier", root / "verify_registry.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
staged = json.loads((root / "workflow-wheel-verification.json").read_text())
published = module.Client().get_json("https://pypi.org/pypi/agent-guard-python/0.2.10/json")
module.need(published.get("info", {}).get("version") == "0.2.10", "PyPI version mismatch")
files = published.get("urls", [])
module.need(len(files) == 5, "PyPI file matrix incomplete")
expected = {item["wheel"]: item for item in staged["wheels"]}
for item in files:
    row = expected.pop(item.get("filename"), None)
    module.need(row is not None and item.get("yanked") is False, "unexpected/yanked PyPI file")
    module.need(item.get("digests", {}).get("sha256") == row["sha256"] and item.get("size") == row["bytes"], "PyPI file differs from preapproved workflow artifact")
module.need(not expected, "PyPI missing a staged wheel")
with (root / "pypi-metadata-check.json").open("x", encoding="utf-8") as handle:
    json.dump({"version": "0.2.10", "release_run": 40112534342, "source": staged["source_commit"], "success": True, "files": [{"name": item["filename"], "sha256": item["digests"]["sha256"]} for item in files], "scope": "Public metadata matches five independently checked workflow files; full registry artifact downloads follow separately."}, handle, indent=2)
    handle.write("\n")
print("PyPI lists exactly the five preapproved workflow wheel hashes and sizes.")
