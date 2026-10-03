#!/usr/bin/env python3
"""Check and update live source-version markers without rewriting release history."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib


SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class VersionError(RuntimeError):
    pass


def read_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def marker(path: Path, pattern: str, label: str) -> str:
    matches = re.findall(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if len(matches) != 1:
        raise VersionError(f"expected exactly one {label} marker in {path}, found {len(matches)}")
    value = matches[0]
    if isinstance(value, tuple):
        value = value[0]
    return value


def collect_local_dependency_versions(root: Path) -> dict[str, str]:
    versions: dict[str, str] = {}

    def visit(value, trail: tuple[str, ...], manifest: Path) -> None:
        if isinstance(value, dict):
            dependency_tables = {"dependencies", "dev-dependencies", "build-dependencies"}
            is_dependency = any(component in dependency_tables for component in trail)
            if is_dependency and "path" in value and isinstance(value["path"], str):
                dependency = ".".join(trail)
                version = value.get("version")
                if not isinstance(version, str):
                    raise VersionError(
                        f"local dependency {dependency} in {manifest} has no exact version pin"
                    )
                versions[f"{manifest.relative_to(root)}:{dependency}"] = version
            for key, child in value.items():
                visit(child, (*trail, str(key)), manifest)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*trail, str(index)), manifest)

    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        visit(read_toml(manifest), (), manifest)
    return versions


def collect_versions(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    cargo = read_toml(root / "Cargo.toml")
    source = {"Cargo.toml workspace.package.version": cargo["workspace"]["package"]["version"]}

    source["root pyproject.toml"] = read_toml(root / "pyproject.toml")["project"]["version"]
    source["Python crate pyproject.toml"] = read_toml(
        root / "crates/agent-guard-python/pyproject.toml"
    )["project"]["version"]

    node_package = read_json(root / "crates/agent-guard-node/package.json")
    node_lock = read_json(root / "crates/agent-guard-node/package-lock.json")
    source["Node package.json"] = node_package["version"]
    source["Node package-lock.json top-level"] = node_lock["version"]
    source["Node package-lock.json root package"] = node_lock["packages"][""]["version"]

    source["Claude plugin.json"] = read_json(root / ".claude-plugin/plugin.json")["version"]
    source["Claude marketplace.json"] = read_json(root / ".claude-plugin/marketplace.json")[
        "plugins"
    ][0]["version"]
    source["npm installer package.json"] = read_json(
        root / "packages/agent-guard-plugin/package.json"
    )["version"]

    readme = root / "README.md"
    docs_readme = root / "docs/README.md"
    plugin_guide = root / "docs/guides/operations/claude-code-plugin.md"
    python_readme = root / "crates/agent-guard-python/README.md"

    badge = marker(readme, r"Version-([0-9A-Za-z.+\-]+)-blue", "README badge")
    source["README badge"] = badge.replace("--", "-")
    source["README source version"] = marker(
        readme, r"Source version\*\*:\s*`v([0-9A-Za-z.+\-]+)`", "README source version"
    )
    source["docs/README title"] = marker(
        docs_readme,
        r"Documentation Hub \(v([0-9A-Za-z.+\-]+)\)",
        "docs/README title version",
    )
    source["docs/README source version"] = marker(
        docs_readme,
        r"Source version\*\*\s*(?:→|:)\s*`v([0-9A-Za-z.+\-]+)`",
        "docs/README source version",
    )
    source["CLAUDE.md current source"] = marker(
        root / "CLAUDE.md",
        r"Current source version:\s*([0-9A-Za-z.+\-]+)\.",
        "CLAUDE.md current source version",
    )
    source["CONTRIBUTING.md exact pin example"] = marker(
        root / "CONTRIBUTING.md",
        r'matches the `version = "=([0-9A-Za-z.+\-]+)"` inter-crate pin',
        "CONTRIBUTING.md exact pin example",
    )
    source["plugin guide preview status"] = marker(
        plugin_guide,
        r"\| \*\*Status\*\* \| .*?\(v([0-9A-Za-z.+\-]+)\) \|",
        "plugin guide preview status",
    )
    for binary in ("guard-hook", "agent-guard-cli"):
        source[f"plugin guide {binary} install"] = marker(
            plugin_guide,
            rf"cargo install {binary} --version ([0-9A-Za-z.+\-]+) --locked --force",
            f"plugin guide {binary} install",
        )
    source["Python README unreleased source"] = marker(
        python_readme,
        r"unreleased `([0-9A-Za-z.+\-]+)` source",
        "Python README unreleased source",
    )

    workspace_names = {
        read_toml(manifest)["package"]["name"]
        for manifest in sorted((root / "crates").glob("*/Cargo.toml"))
    }
    lock_packages = read_toml(root / "Cargo.lock")["package"]
    for name in sorted(workspace_names):
        matches = [package["version"] for package in lock_packages if package["name"] == name]
        if len(matches) != 1:
            raise VersionError(f"expected one Cargo.lock workspace package named {name}, found {len(matches)}")
        source[f"Cargo.lock package {name}"] = matches[0]

    for label, version in collect_local_dependency_versions(root).items():
        if not version.startswith("="):
            raise VersionError(f"local dependency {label} is not exact-pinned: {version}")
        source[f"local dependency {label}"] = version[1:]

    published = {
        "README published release": marker(
            readme,
            r"Latest published release\*\*:\s*\[`v([0-9A-Za-z.+\-]+)`",
            "README published release",
        ),
        "README additional release link": marker(
            readme,
            r"^- \[Latest published release\]\([^\n]*/tag/v([0-9A-Za-z.+\-]+)\)$",
            "README additional release link",
        ),
        "docs/README published release": marker(
            docs_readme,
            r"Latest published release\*\*\s*(?:→|:)\s*\[`v([0-9A-Za-z.+\-]+)`",
            "docs/README published release",
        ),
        "Python README latest package": marker(
            python_readme,
            r"latest published package is `([0-9A-Za-z.+\-]+)`",
            "Python README latest package",
        ),
        "Python README published install": marker(
            python_readme,
            r"python -m pip install agent-guard-python==([0-9A-Za-z.+\-]+)",
            "Python README published install",
        ),
    }
    return source, published


def assert_consistent(root: Path) -> tuple[str, str]:
    source, published = collect_versions(root)
    expected_source = source["Cargo.toml workspace.package.version"]
    for label, actual in source.items():
        if actual != expected_source:
            raise VersionError(
                f"source version mismatch for {label}: expected {expected_source}, got {actual}"
            )

    expected_published = published["README published release"]
    for label, actual in published.items():
        if actual != expected_published:
            raise VersionError(
                f"published version mismatch for {label}: expected {expected_published}, got {actual}"
            )
    return expected_source, expected_published


def replace_one(path: Path, pattern: str, replacement: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise VersionError(f"expected exactly one {label} marker in {path}, found {count}")
    path.write_text(updated, encoding="utf-8")


def _apply_bump(root: Path, new: str) -> tuple[str, str]:
    if not SEMVER.fullmatch(new):
        raise VersionError(f"new version is not valid SemVer: {new}")
    old, published = assert_consistent(root)
    if new == old:
        return old, published

    escaped = re.escape(old)
    replace_one(
        root / "Cargo.toml",
        rf'(\[workspace\.package\][\s\S]*?^version\s*=\s*"){escaped}("\s*$)',
        rf"\g<1>{new}\g<2>",
        "workspace package version",
    )
    for rel in ("pyproject.toml", "crates/agent-guard-python/pyproject.toml"):
        replace_one(
            root / rel,
            rf'(\[project\][\s\S]*?^version\s*=\s*"){escaped}("\s*$)',
            rf"\g<1>{new}\g<2>",
            f"{rel} project version",
        )

    for rel in (
        "crates/agent-guard-node/package.json",
        ".claude-plugin/plugin.json",
        "packages/agent-guard-plugin/package.json",
    ):
        replace_one(
            root / rel,
            rf'^(\s*"version"\s*:\s*"){escaped}(",?\s*)$',
            rf"\g<1>{new}\g<2>",
            f"{rel} top-level version",
        )
    replace_one(
        root / ".claude-plugin/marketplace.json",
        rf'^(\s+"version"\s*:\s*"){escaped}(",?\s*)$',
        rf"\g<1>{new}\g<2>",
        "marketplace plugin version",
    )

    node_lock = root / "crates/agent-guard-node/package-lock.json"
    replace_one(
        node_lock,
        rf'^(  "version"\s*:\s*"){escaped}(",\s*)$',
        rf"\g<1>{new}\g<2>",
        "Node lock top-level version",
    )
    replace_one(
        node_lock,
        rf'^(      "version"\s*:\s*"){escaped}(",\s*)$',
        rf"\g<1>{new}\g<2>",
        "Node lock root package version",
    )

    workspace_names: list[str] = []
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        workspace_names.append(read_toml(manifest)["package"]["name"])
        text = manifest.read_text(encoding="utf-8")
        updated, count = re.subn(
            rf'(^[^\n]*path\s*=\s*"[^\n]+?version\s*=\s*"=){escaped}("[^\n]*$)',
            rf"\g<1>{new}\g<2>",
            text,
            flags=re.MULTILINE,
        )
        if count:
            manifest.write_text(updated, encoding="utf-8")

    cargo_lock = root / "Cargo.lock"
    for name in workspace_names:
        replace_one(
            cargo_lock,
            rf'(\[\[package\]\]\nname = "{re.escape(name)}"\nversion = "){escaped}("\n)',
            rf"\g<1>{new}\g<2>",
            f"Cargo.lock package {name}",
        )

    readme = root / "README.md"
    replace_one(
        readme,
        rf"(Version-){re.escape(old.replace('-', '--'))}(-blue)",
        rf"\g<1>{new.replace('-', '--')}\g<2>",
        "README badge",
    )
    replace_one(
        readme,
        rf"(Source version\*\*:\s*`v){escaped}(`)",
        rf"\g<1>{new}\g<2>",
        "README source version",
    )

    docs_readme = root / "docs/README.md"
    replace_one(
        docs_readme,
        rf"(Documentation Hub \(v){escaped}(\))",
        rf"\g<1>{new}\g<2>",
        "docs/README title",
    )
    replace_one(
        docs_readme,
        rf"(Source version\*\*\s*(?:→|:)\s*`v){escaped}(`)",
        rf"\g<1>{new}\g<2>",
        "docs/README source version",
    )
    replace_one(
        root / "CLAUDE.md",
        rf"(Current source version:\s*){escaped}(\.)",
        rf"\g<1>{new}\g<2>",
        "CLAUDE.md current source version",
    )
    replace_one(
        root / "CONTRIBUTING.md",
        rf'(matches the `version = "=){escaped}("` inter-crate pin)',
        rf"\g<1>{new}\g<2>",
        "CONTRIBUTING.md exact pin example",
    )

    plugin_guide = root / "docs/guides/operations/claude-code-plugin.md"
    replace_one(
        plugin_guide,
        rf"(\| \*\*Status\*\* \| .*?\(v){escaped}(\) \|)",
        rf"\g<1>{new}\g<2>",
        "plugin guide preview status",
    )
    for binary in ("guard-hook", "agent-guard-cli"):
        replace_one(
            plugin_guide,
            rf"(cargo install {binary} --version ){escaped}( --locked --force)",
            rf"\g<1>{new}\g<2>",
            f"plugin guide {binary} install",
        )

    replace_one(
        root / "crates/agent-guard-python/README.md",
        rf"(unreleased `){escaped}(` source)",
        rf"\g<1>{new}\g<2>",
        "Python README unreleased source",
    )

    checked_source, checked_published = assert_consistent(root)
    if checked_source != new or checked_published != published:
        raise VersionError("post-bump consistency check produced an unexpected version")
    return old, published


def bump(root: Path, new: str) -> tuple[str, str]:
    """Apply a source-version bump atomically at the file-set level."""
    fixed_paths = [
        root / "Cargo.toml",
        root / "Cargo.lock",
        root / "pyproject.toml",
        root / "README.md",
        root / "CLAUDE.md",
        root / "CONTRIBUTING.md",
        root / "docs/README.md",
        root / "docs/guides/operations/claude-code-plugin.md",
        root / "crates/agent-guard-node/package.json",
        root / "crates/agent-guard-node/package-lock.json",
        root / "crates/agent-guard-python/pyproject.toml",
        root / "crates/agent-guard-python/README.md",
        root / ".claude-plugin/plugin.json",
        root / ".claude-plugin/marketplace.json",
        root / "packages/agent-guard-plugin/package.json",
    ]
    paths = fixed_paths + sorted((root / "crates").glob("*/Cargo.toml"))
    originals = {path: path.read_bytes() for path in paths}
    try:
        return _apply_bump(root, new)
    except BaseException:
        for path, content in originals.items():
            path.write_bytes(content)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "bump", "current"))
    parser.add_argument("version", nargs="?")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    try:
        if args.command == "check":
            source, published = assert_consistent(args.root.resolve())
            print(f"Version consistency check passed: source {source}, published release {published}")
        elif args.command == "current":
            source, _ = assert_consistent(args.root.resolve())
            print(source)
        else:
            if args.version is None:
                parser.error("bump requires a version")
            old, published = bump(args.root.resolve(), args.version)
            print(f"bumped source {old} -> {args.version}; published release remains {published}")
    except (KeyError, OSError, ValueError, VersionError, tomllib.TOMLDecodeError) as error:
        print(f"version marker error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
