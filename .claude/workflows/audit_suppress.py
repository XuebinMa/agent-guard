#!/usr/bin/env python3
"""Suppression helper for weekly-deep-audit.sh.

Reads docs/audits/suppressions.yaml and supports two subcommands:

  prompt-block <agent>      Emit a "do NOT re-report" markdown block listing the
                            dispositioned findings relevant to <agent>, for
                            appending to that agent's prompt (feed-forward).

  filter <agent> <file>     Read a captured agent report (<file>), move any
                            finding whose text matches a suppression into a
                            collapsed "Suppressed (known)" footer, and print the
                            filtered report (post-filter safety net).

<agent> is one of: silent-failure | security-bounty | type-design.

Fail-open by design: on a missing/unparseable suppressions file, prompt-block
prints nothing and filter passes the report through unchanged, so a broken
suppressions file can never block or corrupt the weekly audit.
"""
from __future__ import annotations

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUPPRESSIONS = os.path.join(REPO_ROOT, ".claude", "audit-suppressions.yaml")


def _load_entries() -> list[dict]:
    """Parse suppressions.yaml into a list of entry dicts. Returns [] on any
    failure (fail-open)."""
    try:
        with open(SUPPRESSIONS, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return []

    # Prefer PyYAML when available; fall back to a minimal parser for the
    # controlled subset this file uses (no external dependency required).
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
        entries = data.get("suppressions", []) or []
        return [e for e in entries if isinstance(e, dict)]
    except Exception:
        return _parse_minimal(text)


def _parse_minimal(text: str) -> list[dict]:
    """Minimal parser for the entry shape this repo authors: a `suppressions:`
    list of `- id:` blocks with `key: value` scalars and a `match: [..]` list."""
    entries: list[dict] = []
    cur: dict | None = None
    in_list = False
    for raw in text.splitlines():
        line = raw if _in_quotes_hash(raw) else raw.split("#", 1)[0]
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "suppressions:":
            in_list = True
            continue
        if not in_list:
            continue
        if stripped.startswith("- "):
            if cur:
                entries.append(cur)
            cur = {}
            stripped = stripped[2:].strip()
        if cur is None:
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "match":
            cur[key] = _parse_inline_list(value)
        else:
            cur[key] = _unquote(value)
    if cur:
        entries.append(cur)
    return [e for e in entries if e.get("id")]


def _in_quotes_hash(line: str) -> bool:
    # Treat a `#` inside a quoted value as data, not a comment. Cheap heuristic:
    # if the part before the first `#` has an odd number of quotes, keep the line.
    head = line.split("#", 1)[0]
    return head.count('"') % 2 == 1


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_inline_list(value: str) -> list[str]:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    items = []
    for part in value.split(","):
        part = part.strip()
        if part:
            items.append(_unquote(part))
    return items


def _applies(entry: dict, agent: str) -> bool:
    scope = (entry.get("scope") or "all").strip()
    return scope in (agent, "all")


def _matches(entry: dict, text: str) -> bool:
    needles = entry.get("match") or []
    if not needles:
        return False
    hay = text.lower()
    return all(str(n).lower() in hay for n in needles)


def cmd_prompt_block(agent: str) -> int:
    entries = [e for e in _load_entries() if _applies(e, agent)]
    if not entries:
        return 0
    out = [
        "",
        "### Known and already-dispositioned — do NOT re-report",
        "",
        "The findings below are intentionally accepted, tracked elsewhere, or "
        "guarded by other means. Do NOT include them (or restatements of them) "
        "in your report:",
        "",
    ]
    for e in entries:
        ref = e.get("ref")
        ref_str = f" ({e.get('disposition', 'dispositioned')}{', ' + ref if ref else ''})"
        tokens = ", ".join(e.get("match") or [])
        out.append(f"- {e.get('id')}{ref_str}: {e.get('rationale', '')} [signals: {tokens}]")
    out.append("")
    sys.stdout.write("\n".join(out))
    return 0


def _split_findings(text: str) -> list[tuple[str, str]]:
    """Split a report into ordered (kind, chunk) parts where kind is 'finding'
    (a top-level `- ` bullet plus its indented continuation) or 'text'."""
    lines = text.splitlines()
    parts: list[tuple[str, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        if lines[i].startswith("- "):
            block = [lines[i]]
            i += 1
            while i < n:
                nxt = lines[i]
                if nxt.startswith("- ") or nxt.startswith("#") or nxt.startswith("---"):
                    break
                # A continuation line is blank or indented. A non-indented,
                # non-blank line (e.g. a trailing "Note: ..." paragraph) is NOT
                # part of this finding — stop so its text is not matched against
                # suppressions on the finding's behalf and wrongly suppress it.
                if nxt.strip() and not (nxt.startswith(" ") or nxt.startswith("\t")):
                    break
                block.append(nxt)
                i += 1
            parts.append(("finding", "\n".join(block).rstrip()))
        else:
            parts.append(("text", lines[i]))
            i += 1
    return parts


def cmd_filter(agent: str, path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return 0
    entries = [e for e in _load_entries() if _applies(e, agent)]
    if not entries:
        sys.stdout.write(text)
        return 0

    kept: list[str] = []
    suppressed: list[str] = []
    for kind, chunk in _split_findings(text):
        if kind == "finding" and any(_matches(e, chunk) for e in entries):
            suppressed.append(chunk)
        else:
            kept.append(chunk)

    sys.stdout.write("\n".join(kept).rstrip() + "\n")
    if suppressed:
        sys.stdout.write(
            f"\n<details>\n<summary>Suppressed ({len(suppressed)} known — see "
            f".claude/audit-suppressions.yaml)</summary>\n\n"
            + "\n".join(suppressed).rstrip()
            + "\n</details>\n"
        )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: audit_suppress.py prompt-block <agent> | filter <agent> <file>\n")
        return 64
    sub = argv[1]
    if sub == "prompt-block" and len(argv) >= 3:
        return cmd_prompt_block(argv[2])
    if sub == "filter" and len(argv) >= 4:
        return cmd_filter(argv[2], argv[3])
    sys.stderr.write("usage: audit_suppress.py prompt-block <agent> | filter <agent> <file>\n")
    return 64


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
