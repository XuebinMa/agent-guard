#!/usr/bin/env python3
"""One-off public registry artifact verification; never executes downloaded code.

Writes only the explicitly named JSON evidence file beside this script. Network
errors, unexpected statuses/shapes and unmet checks are failures, not absence.
SLSA statement checks here do NOT authenticate signatures: npm audit signatures
must be run separately by the release operator against the installed package.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import email
import gzip
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

CRATES = (
    "agent-guard-core", "agent-guard-validators", "agent-guard-sandbox",
    "agent-guard-sdk", "agent-guard-broker", "agent-guard-cli",
    "guard-hook", "guard-verify",
)
BINARIES = {"agent-guard-cli", "guard-hook", "guard-verify"}
INTERNAL = set(CRATES) | {"agent-guard-python", "agent-guard-node"}
REPOSITORY = "https://github.com/XuebinMa/agent-guard"
WORKFLOW = ".github/workflows/release.yml"
HOSTS = {
    "crates.io", "static.crates.io", "pypi.org",
    "files.pythonhosted.org", "registry.npmjs.org",
}
META_CAP = 4 * 1024 * 1024
ARTIFACT_CAP = 64 * 1024 * 1024
UNPACKED_CAP = 256 * 1024 * 1024
TOTAL_CAP = 512 * 1024 * 1024
FILE_CAP = 64 * 1024 * 1024
WRAPPERS = {
    "agent_guard/__init__.py", "agent_guard/adapters.py",
    "agent_guard/langchain.py", "agent_guard/openai.py",
}
PLATFORMS = {
    "macosx_10_12_x86_64": "macOS x86_64",
    "macosx_11_0_arm64": "macOS arm64",
    "manylinux_2_17_aarch64.manylinux2014_aarch64": "Linux aarch64",
    "manylinux_2_17_x86_64.manylinux2014_x86_64": "Linux x86_64",
    "win_amd64": "Windows amd64",
}


class VerificationError(Exception):
    pass


def need(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def json_bytes(data: bytes):
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as error:
        raise VerificationError(f"invalid JSON response: {error}") from error


def allowed_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    need(
        parsed.scheme == "https" and parsed.hostname in HOSTS
        and parsed.port in (None, 443) and parsed.username is None
        and parsed.password is None and not parsed.fragment,
        "refusing non-public-registry HTTPS URL",
    )
    return url


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        allowed_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(SafeRedirect())
        self.total = 0

    def _read(self, response, cap: int) -> bytes:
        length = response.headers.get("Content-Length")
        if length is not None:
            try:
                need(int(length) <= cap, "response Content-Length exceeds cap")
            except ValueError as error:
                raise VerificationError("invalid response Content-Length") from error
        start = time.monotonic()
        chunks = []
        size = 0
        while True:
            need(time.monotonic() - start <= 90, "response read exceeded time bound")
            chunk = response.read(min(65536, cap + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            self.total += len(chunk)
            need(size <= cap, "response exceeds byte cap")
            need(self.total <= TOTAL_CAP, "session download cap exceeded")
            chunks.append(chunk)
        return b"".join(chunks)

    def fetch(self, url: str, cap: int = META_CAP) -> tuple[int, bytes]:
        allowed_url(url)
        for attempt in range(3):
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "agent-guard-release-verification/0.2.10 (public-read-only)",
                    "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.1",
                },
            )
            try:
                with self.opener.open(request, timeout=20) as response:
                    need(response.status == 200, f"unexpected HTTP {response.status}")
                    return 200, self._read(response, cap)
            except urllib.error.HTTPError as error:
                with error:
                    body = self._read(error, min(cap, META_CAP))
                if error.code == 404:
                    return 404, body
                if error.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise VerificationError(f"registry returned HTTP {error.code}") from error
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                raise VerificationError(f"registry network failure: {error}") from error
        raise VerificationError("registry retry bound exhausted")

    def get(self, url: str, cap: int = META_CAP) -> bytes:
        status, body = self.fetch(url, cap)
        need(status == 200, f"required registry artifact not available: HTTP {status}")
        return body

    def get_json(self, url: str):
        return json_bytes(self.get(url))


def absence_status(status: int) -> bool:
    if status == 404:
        return True
    if status == 200:
        return False
    raise VerificationError(f"HTTP {status} is not definitive version absence")


def require_digest(data: bytes, algorithm: str, expected: str) -> str:
    actual = hashlib.new(algorithm, data).hexdigest()
    need(actual == expected.lower(), f"{algorithm} artifact checksum mismatch")
    return actual


def crate_artifact_url(crate: str, version: str) -> str:
    need(crate in CRATES and re.fullmatch(r"\d+\.\d+\.\d+", version) is not None,
         "unsupported crate artifact identity")
    # The crates.io API may negotiate JSON {url: ...}, not archive bytes.
    return f"https://static.crates.io/crates/{crate}/{crate}-{version}.crate"


def safe_member(name: str) -> None:
    path = PurePosixPath(name)
    need(
        bool(name) and not path.is_absolute() and ".." not in path.parts
        and "\\" not in name and "\x00" not in name,
        "unsafe archive member name",
    )


def tar_contents(data: bytes) -> dict[str, bytes]:
    result = {}
    total = 0
    count = 0
    try:
        # Bound decompression before tarfile can process extended/PAX headers.
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            expanded = compressed.read(UNPACKED_CAP + 1)
        need(len(expanded) <= UNPACKED_CAP, "gzip tar expansion exceeds cap")
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for member in archive:
                count += 1
                need(count <= 10000, "too many tar members")
                safe_member(member.name)
                need(member.isdir() or member.isfile(), "tar links/special files are not permitted")
                if member.isdir():
                    continue
                need(0 <= member.size <= FILE_CAP, "tar member exceeds file cap")
                total += member.size
                need(total <= UNPACKED_CAP, "tar expansion exceeds cap")
                need(member.name not in result, "duplicate tar member")
                stream = archive.extractfile(member)
                need(stream is not None, "regular tar member has no data")
                with stream:
                    body = stream.read(member.size + 1)
                need(len(body) == member.size, "tar member size mismatch")
                result[member.name] = body
    except (tarfile.TarError, OSError, EOFError) as error:
        raise VerificationError(f"invalid bounded tar archive: {error}") from error
    return result


def toml_bytes(data: bytes) -> dict:
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"invalid packaged TOML: {error}") from error


def manifest_pins(manifest: dict, version: str) -> list[dict]:
    found = []

    def walk(value, trail=()):
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            if key in ("dependencies", "dev-dependencies", "build-dependencies") and isinstance(child, dict):
                for dependency, spec in child.items():
                    name = spec.get("package", dependency) if isinstance(spec, dict) else dependency
                    if name in INTERNAL:
                        need(isinstance(spec, dict) and spec.get("version") == f"={version}",
                             f"internal dependency {name} lacks exact registry version")
                        need("path" not in spec and "git" not in spec,
                             "normalized registry manifest retains a local/git dependency")
                        found.append({"crate": name, "version": spec["version"], "table": ".".join((*trail, key))})
            walk(child, (*trail, key))

    walk(manifest)
    return found


def lock_checks(data: bytes, version: str, *, require_tokio: bool = False) -> dict:
    packages = toml_bytes(data).get("package")
    need(isinstance(packages, list), "packaged Cargo.lock lacks packages")
    versions = {}
    for package in packages:
        name, resolved = package.get("name"), package.get("version")
        need(isinstance(name, str) and isinstance(resolved, str), "invalid lock package")
        versions.setdefault(name, []).append(resolved)
        if name in INTERNAL:
            need(resolved == version, f"packaged lock contains a stale internal version: {name}")
    need("unsafe-libyaml" not in versions and "serde_yaml" not in versions,
         "retired policy parser remains in packaged lock")
    minima = {
        "serde-saphyr": (2, 0, 0),
        "quinn-proto": (0, 11, 18),
        "rustls": (0, 23, 46),
        "rustls-webpki": (0, 103, 16),
        "webpki-root-certs": (1, 0, 10),
    }
    checked = {}
    for name, minimum in minima.items():
        if name not in versions:
            continue
        for resolved in versions[name]:
            need(re.fullmatch(r"\d+\.\d+\.\d+", resolved) is not None,
                 f"unexpected prerelease security dependency: {name}")
            actual = tuple(map(int, resolved.split(".")))
            need(actual >= minimum, f"packaged lock has unpatched {name} {resolved}")
        checked[name] = versions[name]
    need("serde-saphyr" in checked, "packaged lock is missing the new policy parser")
    if require_tokio:
        need("tokio" in versions, "SDK/binary lock is missing required Tokio")
    for name, expected in (("tokio", "1.51.6"), ("process-wrap", "10.0.1")):
        if name in versions:
            need(versions[name] == [expected], f"packaged lock differs from the reviewed {name} {expected}")
            checked[name] = versions[name]
    return {"sha256": hashlib.sha256(data).hexdigest(), "security_versions": checked}


def verify_crate(client: Client, crate: str, version: str, commit: str, source: Path) -> dict:
    url = f"https://crates.io/api/v1/crates/{crate}/{version}"
    payload = client.get_json(url)
    metadata = payload.get("version")
    need(isinstance(metadata, dict), f"{crate} version response has wrong shape")
    need(metadata.get("num") == version and metadata.get("crate") == crate,
         "crate API exact version/name mismatch")
    need(metadata.get("yanked") is False, "published crate is yanked")
    checksum = metadata.get("checksum")
    need(isinstance(checksum, str) and re.fullmatch(r"[a-fA-F0-9]{64}", checksum) is not None,
         "crate API checksum is missing or invalid")
    expected_path = f"/api/v1/crates/{crate}/{version}/download"
    need(metadata.get("dl_path", expected_path) == expected_path, "unexpected crate download path")
    data = client.get(crate_artifact_url(crate, version), ARTIFACT_CAP)
    require_digest(data, "sha256", checksum)
    files = tar_contents(data)
    prefix = f"{crate}-{version}/"
    need(all(name.startswith(prefix) for name in files), "crate archive prefix mismatch")
    manifest_name = prefix + "Cargo.toml"
    vcs_name = prefix + ".cargo_vcs_info.json"
    need(manifest_name in files and vcs_name in files, "crate lacks manifest or VCS metadata")
    manifest = toml_bytes(files[manifest_name])
    package = manifest.get("package", {})
    need(package.get("name") == crate and package.get("version") == version,
         "packaged crate manifest identity mismatch")
    vcs = json_bytes(files[vcs_name])
    need(vcs.get("git", {}).get("sha1") == commit, "crate VCS commit differs from release commit")
    need(vcs.get("git", {}).get("dirty", False) is False, "crate was packaged from a dirty tree")
    need(vcs.get("path_in_vcs") == f"crates/{crate}", "crate VCS source path mismatch")
    pins = manifest_pins(manifest, version)
    if crate == "agent-guard-core":
        need(package.get("rust-version") == "1.89", "policy core MSRV mismatch")
        parser = manifest.get("dependencies", {}).get("serde-saphyr", {})
        need(isinstance(parser, dict) and parser.get("default-features") is False
             and set(parser.get("features", [])) == {"deserialize"},
             "packaged parser features are not deserialize-only")
        need("serde_yaml" not in manifest.get("dependencies", {}), "old parser manifest remains")
    lock_name = prefix + "Cargo.lock"
    if crate in BINARIES:
        need(lock_name in files, "installable binary crate is missing Cargo.lock")
    require_tokio = crate in BINARIES or crate == "agent-guard-sdk"
    if require_tokio:
        need(lock_name in files, "SDK/binary package lacks its dependency lock")
    lock = lock_checks(files[lock_name], version, require_tokio=require_tokio) if lock_name in files else None
    if crate in {"agent-guard-broker", "agent-guard-cli", "guard-hook"}:
        need(lock is not None and lock["security_versions"].get("process-wrap") == ["10.0.1"],
             "Broker/CLI/hook package lacks the reviewed process wrapper")
    selected = {
        "agent-guard-broker": ["src/grant.rs", "src/git.rs", "src/git/process.rs", "src/execute.rs", "src/receipt.rs"],
        "agent-guard-cli": ["src/main.rs"],
        "agent-guard-sdk": ["src/approval.rs", "src/jsonl_file.rs"],
    }.get(crate, [])
    patch_hashes = {}
    for relative in selected:
        packaged = prefix + relative
        need(packaged in files, f"packaged repair source is missing: {relative}")
        result = subprocess.run(
            ["git", "-C", str(source), "show", f"{commit}:crates/{crate}/{relative}"],
            capture_output=True, timeout=30, check=False,
        )
        need(result.returncode == 0, "cannot read exact release-tree repair source")
        need(result.stdout == files[packaged], f"packaged repair source differs from release tree: {crate}/{relative}")
        patch_hashes[relative] = hashlib.sha256(result.stdout).hexdigest()
    fixture_digests = {}
    if crate == "guard-verify":
        for filename, digest in {
            "bundle_vectors_v1.json": "1663000a67f38fcd54ff4856b39583b17ffec342f13f8d0921e2de0bc2bc25c5",
            "envelope_vectors_v1.json": "a8be5ff764a86122ca09e94340416b7169531bf5d0cc76a0b1fc87f8272eb16e",
        }.items():
            fixture_name = prefix + "fixtures/attenu/" + filename
            need(fixture_name in files, "guard-verify crate is missing a pinned corpus fixture")
            fixture_digests[filename] = require_digest(files[fixture_name], "sha256", digest)
    return {
        "crate": crate, "version": version, "yanked": False, "checksum": checksum,
        "download_bytes": len(data), "vcs_commit": commit,
        "manifest_internal_pins": pins, "packaged_lock": lock,
        "fixture_digests": fixture_digests,
        "repair_source_hashes": patch_hashes,
    }


def wheel_members(data: bytes) -> tuple[zipfile.ZipFile, dict]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        entries = archive.infolist()
        need(len(entries) <= 10000, "too many wheel members")
        names = {}
        total = 0
        for item in entries:
            safe_member(item.filename)
            need(item.filename not in names, "duplicate wheel member")
            need(not item.flag_bits & 1, "encrypted wheel member")
            mode = item.external_attr >> 16
            need(not stat.S_ISLNK(mode), "wheel symlink is not permitted")
            need(item.file_size <= FILE_CAP, "wheel member exceeds file cap")
            total += item.file_size
            need(total <= UNPACKED_CAP, "wheel expansion exceeds cap")
            need(".dSYM" not in item.filename and "__pycache__" not in item.filename
                 and not item.filename.endswith((".pyc", ".pyo")), "wheel contains build contamination")
            names[item.filename] = item
        need(WRAPPERS <= names.keys(), "wheel is missing Python wrapper modules")
        return archive, names
    except (zipfile.BadZipFile, OSError) as error:
        raise VerificationError(f"invalid wheel archive: {error}") from error


def verify_record(archive: zipfile.ZipFile, names: dict, record_name: str) -> None:
    need(record_name in names, "wheel lacks RECORD")
    rows = csv.reader(io.StringIO(archive.read(record_name).decode("utf-8")))
    recorded = set()
    for row in rows:
        need(len(row) == 3, "invalid wheel RECORD row")
        name, digest, size = row
        need(name in names and name not in recorded, "RECORD name missing/duplicated")
        recorded.add(name)
        if name == record_name:
            need(not digest and not size, "RECORD self-entry must not contain its own digest")
            continue
        body = archive.read(name)
        need(size == str(len(body)), "wheel RECORD size mismatch")
        need(digest.startswith("sha256="), "unsupported/missing RECORD hash")
        actual = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        need(digest == "sha256=" + actual, "wheel RECORD checksum mismatch")
    expected = {name for name, item in names.items() if not item.is_dir()}
    need(recorded == expected, "wheel RECORD does not account for every packaged file")


def wheel_sbom(data: bytes, version: str) -> dict:
    document = json_bytes(data)
    need(document.get("bomFormat") == "CycloneDX", "wheel SBOM format mismatch")
    root = document.get("metadata", {}).get("component", {})
    need(root.get("name") == "agent-guard-python" and root.get("version") == version,
         "wheel SBOM root identity mismatch")
    components = document.get("components")
    need(isinstance(components, list), "wheel SBOM lacks components")
    tokio = [item.get("version") for item in components if isinstance(item, dict) and item.get("name") == "tokio"]
    need(tokio == ["1.51.6"], "wheel SBOM does not contain the reviewed Tokio 1.51.6")
    for item in components:
        if isinstance(item, dict) and item.get("name") in INTERNAL:
            need(item.get("version") == version, "wheel SBOM contains a stale internal package")
    return {"sha256": hashlib.sha256(data).hexdigest(), "format": "CycloneDX", "tokio": tokio}


def verify_wheels(client: Client, version: str) -> list[dict]:
    payload = client.get_json(f"https://pypi.org/pypi/agent-guard-python/{version}/json")
    info, urls = payload.get("info", {}), payload.get("urls")
    need(info.get("name") == "agent-guard-python" and info.get("version") == version,
         "PyPI distribution identity mismatch")
    need(isinstance(urls, list) and len(urls) == 5, "expected exactly five published wheel files")
    seen = set()
    results = []
    for metadata in urls:
        name = metadata.get("filename")
        need(isinstance(name, str), "PyPI wheel lacks filename")
        prefix = f"agent_guard_python-{version}-cp310-abi3-"
        need(name.startswith(prefix) and name.endswith(".whl"), "unexpected Python/ABI wheel name")
        platform = name[len(prefix):-4]
        need(platform in PLATFORMS and platform not in seen, "wheel platform missing/duplicate/unexpected")
        seen.add(platform)
        need(metadata.get("packagetype") == "bdist_wheel" and metadata.get("yanked") is False,
             "PyPI file is not a non-yanked wheel")
        url = metadata.get("url")
        need(isinstance(url, str) and urllib.parse.urlsplit(url).hostname == "files.pythonhosted.org",
             "unexpected PyPI download host")
        data = client.get(url, ARTIFACT_CAP)
        need(metadata.get("size") == len(data), "PyPI API size mismatch")
        expected_hash = metadata.get("digests", {}).get("sha256")
        need(isinstance(expected_hash, str) and re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None,
             "PyPI SHA256 is missing/invalid")
        require_digest(data, "sha256", expected_hash)
        archive, names = wheel_members(data)
        with archive:
            dist = f"agent_guard_python-{version}.dist-info/"
            need(dist + "METADATA" in names and dist + "WHEEL" in names, "wheel metadata files missing")
            package = email.message_from_bytes(archive.read(dist + "METADATA"))
            need(package.get("Name") == "agent-guard-python" and package.get("Version") == version,
                 "wheel METADATA identity mismatch")
            requires = package.get("Requires-Python", "")
            need(re.fullmatch(r">=\s*3\.10(?:\.0)?", requires) is not None,
                 "wheel Requires-Python differs from >=3.10 contract")
            wheel = email.message_from_bytes(archive.read(dist + "WHEEL"))
            tags = set(wheel.get_all("Tag", []))
            expected_tags = {f"cp310-abi3-{part}" for part in platform.split(".")}
            need(tags == expected_tags, "wheel ABI/platform tags differ from filename")
            need(wheel.get("Root-Is-Purelib", "").lower() == "false", "native wheel claims purelib")
            native = [path for path in names if path.startswith("agent_guard/")
                      and path.endswith((".so", ".pyd"))]
            need(len(native) == 1, "wheel must contain exactly one native extension")
            allowed_native = (
                {"agent_guard/_agent_guard.pyd", "agent_guard/_agent_guard.abi3.pyd"}
                if platform == "win_amd64" else {"agent_guard/_agent_guard.abi3.so"}
            )
            need(native[0] in allowed_native,
                 "wheel native extension does not match agent_guard._agent_guard module")
            verify_record(archive, names, dist + "RECORD")
            sbom_name = dist + "sboms/agent-guard-python.cyclonedx.json"
            need(sbom_name in names, "wheel lacks its build-generated dependency SBOM")
            sbom = wheel_sbom(archive.read(sbom_name), version)
        results.append({
            "wheel": name, "platform": PLATFORMS[platform], "sha256": expected_hash,
            "download_bytes": len(data), "native": native[0], "tags": sorted(tags),
            "record_verified": True, "requires_python": requires,
            "dependency_sbom": sbom,
        })
    need(seen == set(PLATFORMS), "five-platform wheel matrix is incomplete")
    return results


def npm_integrity(data: bytes, integrity: str) -> dict:
    need(isinstance(integrity, str) and integrity.startswith("sha512-")
         and " " not in integrity, "npm dist integrity is not a single sha512 digest")
    try:
        expected = base64.b64decode(integrity[7:], validate=True)
    except ValueError as error:
        raise VerificationError("invalid npm sha512 base64") from error
    need(len(expected) == 64 and hashlib.sha512(data).digest() == expected,
         "npm tarball integrity mismatch")
    return {"sha512": expected.hex(), "sha256": hashlib.sha256(data).hexdigest()}


def provenance_statement(payload: dict, digests: dict, version: str, commit: str, run_id: str) -> dict:
    need(payload.get("_type") == "https://in-toto.io/Statement/v1", "unexpected in-toto statement type")
    need(payload.get("predicateType") == "https://slsa.dev/provenance/v1", "unexpected provenance predicate")
    subjects = payload.get("subject")
    need(isinstance(subjects, list) and len(subjects) == 1, "unexpected provenance subject count")
    subject = subjects[0]
    need(subject.get("name") == f"pkg:npm/agent-guard-plugin@{version}", "provenance package identity mismatch")
    values = subject.get("digest", {})
    matched = False
    for algorithm in ("sha256", "sha512"):
        if algorithm in values:
            need(values[algorithm].lower() == digests[algorithm], "provenance tarball digest mismatch")
            matched = True
    need(matched, "provenance has no supported subject digest")
    predicate = payload.get("predicate", {})
    definition = predicate.get("buildDefinition", {})
    workflow = definition.get("externalParameters", {}).get("workflow", {})
    need(workflow.get("repository") == REPOSITORY and workflow.get("path") == WORKFLOW
         and workflow.get("ref") == f"refs/tags/v{version}", "provenance repository/workflow/tag mismatch")
    dependencies = definition.get("resolvedDependencies", [])
    source = [item for item in dependencies if isinstance(item, dict)
              and item.get("uri") == f"git+{REPOSITORY}@refs/tags/v{version}"
              and item.get("digest", {}).get("gitCommit") == commit]
    need(len(source) == 1, "provenance does not bind the exact release source commit")
    invocation = predicate.get("runDetails", {}).get("metadata", {}).get("invocationId")
    need(isinstance(invocation, str) and re.fullmatch(
        re.escape(REPOSITORY) + rf"/actions/runs/{re.escape(run_id)}/attempts/[1-9]\d*", invocation
    ) is not None, "provenance release workflow run mismatch")
    return {
        "predicate_type": payload["predicateType"], "statement_commit": commit,
        "statement_ref": workflow["ref"], "statement_workflow": workflow["path"],
        "statement_repository": workflow["repository"], "statement_invocation": invocation,
        "subject_integrity_matched": True,
        "cryptographic_signature_verification": "not performed; independently run npm audit signatures",
    }


def verify_npm(client: Client, version: str, commit: str, run_id: str, source: Path) -> dict:
    metadata = client.get_json(f"https://registry.npmjs.org/agent-guard-plugin/{version}")
    need(metadata.get("name") == "agent-guard-plugin" and metadata.get("version") == version,
         "npm exact package identity mismatch")
    need(not any(metadata.get(field) for field in (
        "dependencies", "optionalDependencies", "peerDependencies", "bundleDependencies",
        "bundledDependencies",
    )),
         "npm plugin unexpectedly ships runtime dependencies")
    dist = metadata.get("dist", {})
    tarball = dist.get("tarball")
    need(isinstance(tarball, str) and urllib.parse.urlsplit(tarball).hostname == "registry.npmjs.org",
         "unexpected npm tarball URL")
    data = client.get(tarball, ARTIFACT_CAP)
    digests = npm_integrity(data, dist.get("integrity"))
    files = tar_contents(data)
    need(all(name.startswith("package/") for name in files), "npm tarball prefix mismatch")
    relative = {name[len("package/"):] for name in files}
    required = {"package.json", "bin/cli.js", "lib/init.js", "assets/coding-agent-outbound.yaml", "README.md"}
    need(required <= relative, "npm tarball lacks installer, logic, preset or README")
    need(all(name in {"package.json", "README.md", "LICENSE", "LICENSE.md", "LICENSE.txt"}
             or name.startswith(("bin/", "lib/", "assets/")) for name in relative),
         "unexpected files outside the npm package allow-list")
    package = json_bytes(files["package/package.json"])
    need(package.get("name") == "agent-guard-plugin" and package.get("version") == version,
         "npm packaged manifest identity mismatch")
    need(not any(package.get(field) for field in (
        "dependencies", "optionalDependencies", "peerDependencies", "bundleDependencies",
        "bundledDependencies",
    )),
         "packaged npm plugin has runtime dependencies")
    cli = files["package/bin/cli.js"].decode("utf-8")
    need("const PKG = require('../package.json')" in cli
         and "['install', crate, '--version', PKG.version, '--locked', '--force']" in cli
         and "hasExactVersion(cargoBinary, bin, PKG.version" in cli,
         "npm installer lacks exact-version locked installation/revalidation")
    need("--git" not in cli, "npm installer unexpectedly installs from a Git ref")
    source_hashes = {}
    for source_relative in ("bin/cli.js", "lib/init.js", "assets/coding-agent-outbound.yaml"):
        result = subprocess.run(
            ["git", "-C", str(source), "show", f"{commit}:packages/agent-guard-plugin/{source_relative}"],
            capture_output=True, timeout=30, check=False,
        )
        need(result.returncode == 0, "cannot read exact npm release source")
        need(result.stdout == files["package/" + source_relative], "npm packaged source differs from release tree")
        source_hashes[source_relative] = hashlib.sha256(result.stdout).hexdigest()
    attestations_url = dist.get("attestations", {}).get("url")
    expected_url = f"https://registry.npmjs.org/-/npm/v1/attestations/agent-guard-plugin@{version}"
    need(attestations_url == expected_url, "npm provenance endpoint missing/unexpected")
    bundle_data = client.get(expected_url)
    attested = json_bytes(bundle_data)
    entries = attested.get("attestations")
    need(isinstance(entries, list), "npm attestations response has wrong shape")
    entries = [entry for entry in entries if entry.get("predicateType") == "https://slsa.dev/provenance/v1"]
    need(len(entries) == 1, "npm must supply exactly one SLSA v1 provenance statement")
    envelope = entries[0].get("bundle", {}).get("dsseEnvelope", {})
    need(envelope.get("payloadType") == "application/vnd.in-toto+json", "unexpected DSSE payload type")
    try:
        raw_statement = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, ValueError) as error:
        raise VerificationError("invalid provenance envelope payload") from error
    proof = provenance_statement(json_bytes(raw_statement), digests, version, commit, run_id)
    proof["attestations_url"] = expected_url
    proof["attestation_response_sha256"] = hashlib.sha256(bundle_data).hexdigest()
    proof["statement_sha256"] = hashlib.sha256(raw_statement).hexdigest()
    return {
        "package": "agent-guard-plugin", "version": version, "integrity": dist["integrity"],
        "download_bytes": len(data), "digests": digests, "dependencies": {},
        "package_members": sorted(relative), "installer_locked_and_version_checked": True,
        "provenance_statement": proof,
        "release_source_hashes": source_hashes,
    }


def check_absent(client: Client, version: str) -> dict:
    endpoints = [(crate, f"https://crates.io/api/v1/crates/{crate}/{version}") for crate in CRATES]
    endpoints += [
        ("agent-guard-python", f"https://pypi.org/pypi/agent-guard-python/{version}/json"),
        ("agent-guard-plugin", f"https://registry.npmjs.org/agent-guard-plugin/{version}"),
    ]
    results = []
    for package, url in endpoints:
        status, body = client.fetch(url)
        results.append({"package": package, "url": url, "http_status": status,
                        "definitely_absent": absence_status(status),
                        "response_sha256": hashlib.sha256(body).hexdigest()})
    return {"checks": results, "all_definitely_absent": all(item["definitely_absent"] for item in results)}


def self_test() -> None:
    import importlib.util

    path = Path(__file__).resolve().with_name("registry_verifier_tests.py")
    spec = importlib.util.spec_from_file_location("agent_guard_registry_verifier_tests", path)
    need(spec is not None and spec.loader is not None, "cannot load adjacent offline verifier tests")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run(sys.modules[__name__])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="0.2.10")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--run-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-absent", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    need(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", args.version) is not None,
         "invalid release version")
    need((args.check_absent and args.commit is None)
         or (args.commit is not None and re.fullmatch(r"[0-9a-f]{40}", args.commit) is not None),
         "provide the exact 40-hex final release commit for full verification")
    need((args.check_absent and args.run_id is None)
         or (args.run_id is not None and re.fullmatch(r"[1-9]\d*", args.run_id) is not None),
         "provide the actual release run id for full verification")
    need(args.output is not None, "provide an explicit evidence output JSON")
    need(args.check_absent or (args.source is not None and args.source.is_dir()),
         "provide the release source repository for independent repair-source comparison")
    root = Path(__file__).resolve().parent
    output = args.output.absolute()
    need(output.parent.resolve() == root and not output.is_symlink(),
         "evidence output must be a non-symlink path beside this temporary script")
    need(output.suffix == ".json", "evidence output must have a .json suffix")
    need(not output.exists(), "refusing to overwrite existing evidence; choose a new output filename")
    evidence = {
        "observed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "version": args.version, "source_commit": args.commit,
        "release_run": int(args.run_id) if args.run_id is not None else None,
        "mode": "absence-only" if args.check_absent else "registry-artifact-verification",
        "limits": [
            "No downloaded artifact was executed or installed by this script",
            "Archive content/hash checks are not five-platform execution acceptance",
            "Provenance statement fields are checked but not cryptographically authenticated here",
            "Run npm audit signatures independently and record its actual result",
            "Registry --locked installation and binary/wheel decision smoke remain independent checks",
        ],
    }
    client = Client()
    try:
        if args.check_absent:
            evidence["absence"] = check_absent(client, args.version)
            evidence["success"] = evidence["absence"]["all_definitely_absent"]
        else:
            evidence["rust_crates"] = []
            for crate in CRATES:
                print(f"Verifying public crate {crate} {args.version}", flush=True)
                evidence["rust_crates"].append(verify_crate(client, crate, args.version, args.commit, args.source))
            evidence["python_wheels"] = verify_wheels(client, args.version)
            evidence["npm"] = verify_npm(client, args.version, args.commit, args.run_id, args.source)
            evidence["success"] = True
    except Exception as error:
        evidence["success"] = False
        evidence["error_type"] = type(error).__name__
        evidence["error"] = str(error)
    evidence["downloaded_bytes"] = client.total
    evidence["completed_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    with output.open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"success": evidence["success"], "output": str(output),
                      "error": evidence.get("error")}, ensure_ascii=False))
    return 0 if evidence["success"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"verification refused: {error}", file=sys.stderr)
        raise SystemExit(1)
