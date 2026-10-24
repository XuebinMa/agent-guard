"""Inspect exact-run wheel artifacts and logs before the PyPI approval."""
import email
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
SOURCE = "2da78b1d0b4ad3e62ebc02c09a6d0dd27f836181"
spec = importlib.util.spec_from_file_location("registry_verifier", ROOT / "verify_registry.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
jobs = {
    "win_amd64": (120929131975, "wheel-windows.log"),
    "manylinux_2_17_x86_64.manylinux2014_x86_64": (120929131990, "wheel-linux-x64.log"),
    "manylinux_2_17_aarch64.manylinux2014_aarch64": (120929132024, "wheel-linux-arm64.log"),
    "macosx_11_0_arm64": (120929132039, "wheel-macos-arm64.log"),
    "macosx_10_12_x86_64": (120929132060, "wheel-macos-x64.log"),
}
files = list((ROOT / "workflow-wheels").rglob("*.whl"))
module.need(len(files) == 5, "all five exact-run wheel files are required")
results = []
seen = set()
for path in sorted(files):
    prefix = "agent_guard_python-0.2.10-cp310-abi3-"
    module.need(path.name.startswith(prefix), "unexpected artifact wheel identity")
    platform = path.name[len(prefix):-4]
    module.need(platform in jobs and platform not in seen, "unexpected or repeated platform")
    seen.add(platform)
    data = path.read_bytes()
    archive, names = module.wheel_members(data)
    with archive:
        dist = "agent_guard_python-0.2.10.dist-info/"
        metadata = email.message_from_bytes(archive.read(dist + "METADATA"))
        module.need(metadata["Name"] == "agent-guard-python" and metadata["Version"] == "0.2.10", "wheel metadata differs")
        module.verify_record(archive, names, dist + "RECORD")
        sbom = module.wheel_sbom(archive.read(dist + "sboms/agent-guard-python.cyclonedx.json"), "0.2.10")
    job_id, log_name = jobs[platform]
    log_bytes = (ROOT / log_name).read_bytes()
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", log_bytes.decode("utf-8-sig"))
    module.need(SOURCE in text, "wheel build log lacks exact release source SHA")
    tokio = re.findall(r"(?:Compiling|Fresh) tokio v([0-9.]+)", text)
    module.need(bool(tokio) and set(tokio) == {"1.51.6"}, "wheel log does not demonstrate reviewed Tokio compilation")
    results.append({
        "wheel": path.name,
        "platform": platform,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "record_verified": True,
        "dependency_sbom": sbom,
        "build_job": job_id,
        "build_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "compiled_tokio": tokio,
    })
module.need(seen == set(jobs), "wheel matrix incomplete")
result = {
    "release_run": 40112534342,
    "source_commit": SOURCE,
    "success": True,
    "scope": "Five exact-run archive/log checks before PyPI approval, not five-platform installed execution.",
    "wheels": results,
}
with (ROOT / "workflow-wheel-verification.json").open("x", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2)
    handle.write("\n")
print("Five workflow wheels: source/log/Tokio/SBOM/RECORD checks passed.")
