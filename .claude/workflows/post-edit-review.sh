#!/usr/bin/env bash
#
# .claude/workflows/post-edit-review.sh — Layer 1 real-time review
#
# Wired in .claude/settings.json as a PostToolUse hook on Edit and Write.
# Fires after every successful Edit/Write on a .rs file inside the repo,
# scans the just-written region for the same CRITICAL patterns the
# Layer-2 commit gate enforces, and appends findings to a per-machine
# log. Always exits 0 (warn-only — Layer 1 is informational, never
# blocking).
#
# Pipeline:
#   1. Filter to Edit/Write on `*.rs` paths inside the repo.
#   2. Classify the file path against `.claude/audit-rules.yaml`. Only
#      paths whose rule has `severity_block: CRITICAL` are scanned at
#      edit time; HIGH-classified files are deferred to Layer 2 to
#      avoid edit-rate noise.
#   3. Run the deterministic pattern scan on the new content.
#   4. Per-path 5-second debounce via stamp files under
#      `.claude/.audit-state/stamps/`.
#   5. Append timestamped findings to `.claude/.audit-state/findings.log`
#      and emit a one-line stderr summary.
#
# Implementation note: the python program is materialized to a temp
# file via a top-level heredoc rather than inlined as a heredoc inside
# $(). macOS still ships bash 3.2.57 by default, which has a tokenizer
# bug where a single-quoted heredoc body containing apostrophes
# (e.g. python `r'...'` regex literals) mis-parses when the heredoc
# lives inside command substitution. Top-level heredoc + temp file
# sidesteps that bug.
#
# What this script does NOT do (yet):
#   Spawn LLM reviewer agents (rust-reviewer / security-reviewer /
#   silent-failure-hunter). Synchronous LLM dispatch on every Edit
#   would burn tens of dollars per active developer per day. The
#   `reviewers:` field on the matched rule IS captured into each log
#   line as `would-dispatch=...` so when a future PR enables real
#   dispatch the routing is already settled.
#
# Skip via:
#   AGENT_GUARD_SKIP_POSTEDIT=1   global skip
#   Edits to files under `.claude/` are skipped defensively.
#
# Exit: 0 always — Layer 1 must never block tool execution.

set -uo pipefail

LOG_PREFIX="[post-edit-review]"
DEBOUNCE_SECONDS=5
SEP="|"

# -- 1) Read tool-call JSON and global skip ---------------------------------
INPUT="$(cat || true)"
[[ -z "$INPUT" ]] && exit 0
[[ "${AGENT_GUARD_SKIP_POSTEDIT:-0}" == "1" ]] && exit 0

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[[ -z "$REPO_ROOT" ]] && exit 0
cd "$REPO_ROOT"

RULES_FILE="$REPO_ROOT/.claude/audit-rules.yaml"
[[ -f "$RULES_FILE" ]] || exit 0

STATE_DIR="$REPO_ROOT/.claude/.audit-state"
mkdir -p "$STATE_DIR/stamps" 2>/dev/null || exit 0

# -- 2) Materialize python program to a temp file --------------------------
PY_PROG="$(mktemp -t agg-postedit-prog.XXXXXX)"
PY_OUT="$(mktemp -t agg-postedit-out.XXXXXX)"
trap 'rm -f "$PY_PROG" "$PY_OUT"' EXIT

cat > "$PY_PROG" <<'PYEOF'
import hashlib
import json
import os
import re
import sys

SEP = "|"

try:
    data = json.loads(os.environ.get("INPUT_JSON", ""))
except Exception:
    sys.exit(0)

tool = data.get("tool_name", "")
if tool not in ("Edit", "Write"):
    sys.exit(0)

ti = data.get("tool_input", {}) or {}
fp = ti.get("file_path", "")
if not fp.endswith(".rs"):
    sys.exit(0)

repo_root = os.environ.get("REPO_ROOT", "")
abs_path = fp if fp.startswith("/") else os.path.join(repo_root, fp)
try:
    rel_path = os.path.relpath(abs_path, repo_root)
except ValueError:
    sys.exit(0)
# Defensive: outside-repo OR under .claude/ -> skip.
if rel_path.startswith("..") or rel_path.startswith(".claude/") or rel_path.startswith(".claude" + os.sep):
    sys.exit(0)

# Pick scan body. Edit gives only the new region; Write replaces the
# whole file.
if tool == "Edit":
    body = ti.get("new_string", "") or ""
else:
    body = ti.get("content", "") or ""

# -- audit-rules.yaml: tolerant subset parser (mirrors Layer 2) ------------
def parse_yaml(text):
    try:
        import yaml
        return yaml.safe_load(text).get("rules", []) or []
    except Exception:
        pass
    rules, cur, in_paths, in_revs = [], None, False, False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("  - id:"):
            if cur is not None:
                rules.append(cur)
            cur = {"id": line.split(":", 1)[1].strip(),
                   "paths": [], "reviewers": [], "severity_block": "HIGH"}
            in_paths = in_revs = False
        elif cur is not None and line.startswith("    paths:"):
            in_paths, in_revs = True, False
        elif cur is not None and line.startswith("    reviewers:"):
            in_revs, in_paths = True, False
        elif cur is not None and line.startswith("    severity_block:"):
            cur["severity_block"] = line.split(":", 1)[1].strip()
            in_paths = in_revs = False
        elif cur is not None and line.lstrip().startswith("- "):
            val = line.lstrip()[2:].strip().strip('"').strip("'")
            if in_paths:
                cur["paths"].append(val)
            elif in_revs:
                cur["reviewers"].append(val)
        elif cur is not None and not line.startswith("      "):
            in_paths = in_revs = False
    if cur is not None:
        rules.append(cur)
    return rules

def glob_to_re(pat):
    out, i = "", 0
    while i < len(pat):
        c = pat[i]
        if c == "*" and i + 1 < len(pat) and pat[i + 1] == "*":
            out += ".*"
            i += 2
            if i < len(pat) and pat[i] == "/":
                i += 1
        elif c == "*":
            out += "[^/]*"
            i += 1
        elif c == "?":
            out += "[^/]"
            i += 1
        elif c in r".+()|^$\{}[]":
            out += re.escape(c)
            i += 1
        else:
            out += c
            i += 1
    return re.compile("^" + out + "$")

try:
    text = open(os.environ.get("RULES_PATH", "")).read()
except FileNotFoundError:
    sys.exit(0)

rules = parse_yaml(text)
matched = None
for rule in rules:
    if any(glob_to_re(p).match(rel_path) for p in rule.get("paths", [])):
        matched = rule
        break
if matched is None:
    sys.exit(0)

severity = matched.get("severity_block", "HIGH")
rule_id = matched.get("id", "?")
reviewers = ",".join(matched.get("reviewers", []))

# Layer 1 only fires deterministic checks on CRITICAL-classified paths.
# HIGH paths fall through to Layer 2's commit gate.
if severity != "CRITICAL":
    sys.exit(0)

# -- Pattern scan (mirrors Layer 2) ----------------------------------------
PATTERNS = [
    (re.compile(r"(^|[^A-Za-z_])unsafe\s*[\{\(]"),   "new unsafe block"),
    (re.compile(r"\.unwrap\(\)"),                    "new .unwrap()"),
    (re.compile(r"\.expect\("),                      "new .expect()"),
    (re.compile(r"\bpanic!\s*\("),                   "new panic!()"),
    (re.compile(r"\b(unimplemented|todo)!\s*\("),    "new unimplemented!() / todo!()"),
    (re.compile(r'Command::new\s*\(\s*"(sh|bash)"'), "raw shell Command::new(\"sh|bash\")"),
]

violations = []
for ln_idx, line in enumerate(body.splitlines(), start=1):
    stripped = line.lstrip()
    if stripped.startswith("//") or stripped.startswith("#[") or not stripped:
        continue
    for rx, msg in PATTERNS:
        if rx.search(line):
            # Defensive: drop SEP from emitted snippet so the bash side
            # parses cleanly.
            safe = line.replace(SEP, " ").strip()[:120]
            violations.append((ln_idx, msg, safe))
            break

path_hash = hashlib.sha256(rel_path.encode("utf-8")).hexdigest()

# Schema:  HEADER<SEP>rel_path<SEP>tool<SEP>rule_id<SEP>severity<SEP>reviewers
#          HASH<SEP>sha256(rel_path)
#          FINDING<SEP>line_no<SEP>message<SEP>snippet
print(SEP.join(["HEADER", rel_path, tool, rule_id, severity, reviewers]))
print(SEP.join(["HASH", path_hash]))
for ln, msg, snippet in violations:
    print(SEP.join(["FINDING", str(ln), msg, snippet]))
PYEOF

INPUT_JSON="$INPUT" RULES_PATH="$RULES_FILE" REPO_ROOT="$REPO_ROOT" \
    python3 "$PY_PROG" >"$PY_OUT" 2>/dev/null || true

[[ -s "$PY_OUT" ]] || exit 0

# -- 3) Parse python output -------------------------------------------------
HEADER_LINE="$(grep "^HEADER${SEP}" "$PY_OUT" | head -1)"
HASH_LINE="$(grep "^HASH${SEP}" "$PY_OUT" | head -1)"
FINDING_LINES="$(grep "^FINDING${SEP}" "$PY_OUT" || true)"

[[ -z "$HEADER_LINE" || -z "$HASH_LINE" ]] && exit 0

IFS="$SEP" read -r _h REL_PATH TOOL RULE_ID SEVERITY REVIEWERS <<< "$HEADER_LINE"
IFS="$SEP" read -r _h PATH_HASH <<< "$HASH_LINE"

# -- 4) Per-path debounce ---------------------------------------------------
STAMP="$STATE_DIR/stamps/$PATH_HASH.stamp"
if [[ -e "$STAMP" ]]; then
    NOW_S=$(date +%s)
    STAMP_S=$(stat -f %m "$STAMP" 2>/dev/null || stat -c %Y "$STAMP" 2>/dev/null || echo 0)
    AGE=$(( NOW_S - STAMP_S ))
    if [[ $AGE -lt $DEBOUNCE_SECONDS ]]; then
        exit 0
    fi
fi
touch "$STAMP"

# -- 5) Log + stderr summary -----------------------------------------------
[[ -z "$FINDING_LINES" ]] && exit 0

LOG_FILE="$STATE_DIR/findings.log"
NOW_TS="$(date +"%Y-%m-%dT%H:%M:%S")"
COUNT="$(printf '%s\n' "$FINDING_LINES" | grep -c .)"

while IFS="$SEP" read -r _tag ln msg snippet; do
    [[ -z "${ln:-}" ]] && continue
    printf '%s  %s:%s  CRITICAL  rule=%s  reviewers=%s  %s :: %s\n' \
        "$NOW_TS" "$REL_PATH" "$ln" "$RULE_ID" "$REVIEWERS" "$msg" "$snippet" \
        >> "$LOG_FILE"
done <<< "$FINDING_LINES"

echo "$LOG_PREFIX $COUNT CRITICAL pattern(s) in $REL_PATH (rule=$RULE_ID, would-dispatch=$REVIEWERS); see $LOG_FILE" >&2

exit 0
