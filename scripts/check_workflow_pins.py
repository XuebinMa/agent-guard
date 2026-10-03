#!/usr/bin/env python3
"""Fail when a GitHub Actions workflow uses a mutable external action ref."""

from __future__ import annotations

import re
import sys
from pathlib import Path


USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
PINNED_ACTION_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-fA-F]{40}$"
)


def find_unpinned(workflow_root: Path) -> list[str]:
    violations: list[str] = []
    workflow_dir = workflow_root / ".github" / "workflows"
    paths = sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml"))
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_RE.match(line)
            if match is None:
                continue
            action = match.group(1)
            if action.startswith("./"):
                continue
            if not PINNED_ACTION_RE.fullmatch(action):
                violations.append(
                    f"{path.relative_to(workflow_root)}:{line_number}: "
                    f"external action must use a full 40-hex commit SHA: {action}"
                )
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    violations = find_unpinned(root)
    if violations:
        print("Workflow action pin check failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print("Workflow action pin check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
