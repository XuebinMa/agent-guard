#!/usr/bin/env bash
#
# .claude/workflows/pre-commit-review.sh — Layer 2 audit gate
#
# Wired in .claude/settings.json as a PreToolUse hook on Bash. Reads the tool
# call JSON on stdin, self-filters for `git commit ...` invocations, and
# either allows the commit (exit 0) or blocks it (exit 2 with stderr surfaced
# back to the agent).
#
# Pipeline on a `git commit`:
#   1. cargo fmt --all -- --check                              [CRITICAL gate]
#   2. cargo clippy --workspace --all-features -D warnings     [CRITICAL gate]
#   3. Classify staged .rs files against .claude/audit-rules.yaml
#   4. For files with severity_block=CRITICAL, scan added diff lines for
#      a small set of high-signal patterns (new unsafe / unwrap / panic /
#      shell-out) and block on any match.
#
# What this script does NOT do (yet):
#   - Spawn LLM reviewer agents (rust-reviewer / security-reviewer /
#     silent-failure-hunter). Synchronous LLM dispatch from a hook would add
#     30–120s and dollar cost to every commit. The audit-rules.yaml
#     `reviewers` field is the authoritative future-state list and will be
#     wired in PR-3 (Layer 1, PostToolUse) and a follow-up Layer 2 enhancement.
#
# Overrides:
#   AGENT_GUARD_SKIP_PRECOMMIT=1   skip the gate entirely (emergency only)
#
# Exit codes:
#   0 — allow the commit
#   2 — block the commit; stderr is surfaced to the calling agent

set -uo pipefail

LOG_PREFIX="[pre-commit-review]"

# -- 1) Read tool-call JSON, extract the Bash command -----------------------
# Note: pass JSON via env var, not via pipe. `python3 - <<PY` already binds
# stdin to the heredoc (the program itself), so a piped stdin would be
# silently discarded.
INPUT="$(cat || true)"
COMMAND="$(INPUT_JSON="$INPUT" python3 - <<'PY' 2>/dev/null || true
import json, os, sys
try:
    data = json.loads(os.environ.get("INPUT_JSON", ""))
except Exception:
    sys.exit(0)
if data.get("tool_name") != "Bash":
    sys.exit(0)
print(data.get("tool_input", {}).get("command", ""))
PY
)"

[ -z "$COMMAND" ] && exit 0

# -- 2) Self-filter: only act on `git commit ...` ---------------------------
# Matches `git commit`, `git commit -m ...`, `git commit -am ...`,
# `git commit --amend`, etc. Does NOT match `git commit-tree` or other
# porcelain prefixes that happen to start with `git commit`.
if ! [[ "$COMMAND" =~ (^|[[:space:]])git[[:space:]]+commit([[:space:]]|$) ]]; then
    exit 0
fi

# -- 3) Emergency override --------------------------------------------------
if [[ "${AGENT_GUARD_SKIP_PRECOMMIT:-0}" == "1" ]]; then
    echo "$LOG_PREFIX skipped via AGENT_GUARD_SKIP_PRECOMMIT=1" >&2
    exit 0
fi

# -- 4) Anchor to repo root -------------------------------------------------
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
    echo "$LOG_PREFIX not inside a git working tree; skipping" >&2
    exit 0
fi
cd "$REPO_ROOT"

RULES_FILE="$REPO_ROOT/.claude/audit-rules.yaml"
if [[ ! -f "$RULES_FILE" ]]; then
    echo "$LOG_PREFIX missing $RULES_FILE; skipping (no rules to enforce)" >&2
    exit 0
fi

# -- 5) Pick diff scope -----------------------------------------------------
# `-a`, `-am`, `-ma`, `--all` auto-stage tracked files. For those forms we
# audit `HEAD..worktree` so we don't miss what's about to be auto-staged.
diff_range="--cached"
auto_stage=0
case "$COMMAND" in
    *" --all "*|*" --all="*|*" --all")              auto_stage=1 ;;
esac
# Detect short option clusters containing `a`: -a, -am, -aS, -ams, etc.
# Single-pass python check avoids fragile bash regex.
if [[ $auto_stage -eq 0 ]]; then
    auto_stage="$(COMMAND="$COMMAND" python3 - <<'PY'
import os, re
cmd = os.environ.get("COMMAND", "")
print(1 if re.search(r"(?:^|\s)-[A-Za-z]*a[A-Za-z]*(?:\s|$)", cmd) else 0)
PY
)"
fi

if [[ "$auto_stage" == "1" ]]; then
    diff_range="HEAD"
fi

# -- 6) Collect changed Rust files -----------------------------------------
changed_rs_list="$(git diff "$diff_range" --name-only --diff-filter=ACMR -- '*.rs' 2>/dev/null || true)"

if [[ -z "$changed_rs_list" ]]; then
    echo "$LOG_PREFIX no .rs changes in scope ($diff_range); allowing commit" >&2
    exit 0
fi

# -- 7) Classify changed files against audit-rules.yaml ---------------------
# Output lines: "<path>\t<rule_id>\t<severity_block>". Same env-var-not-pipe
# pattern as step 1 to avoid the heredoc/stdin collision.
classifications="$(CHANGED_LIST="$changed_rs_list" RULES_PATH="$RULES_FILE" python3 - <<'PY'
import os, re, sys

rules_path = os.environ.get("RULES_PATH", "")
changed_list = os.environ.get("CHANGED_LIST", "")

try:
    text = open(rules_path).read()
except FileNotFoundError:
    sys.exit(0)

# Prefer PyYAML when available; fall back to a tolerant subset parser
# that understands the schema we control.
def parse_yaml(text):
    try:
        import yaml
        return yaml.safe_load(text).get("rules", []) or []
    except Exception:
        pass

    rules, cur, in_paths = [], None, False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("  - id:"):
            if cur is not None:
                rules.append(cur)
            cur = {"id": line.split(":", 1)[1].strip(),
                   "paths": [], "severity_block": "HIGH"}
            in_paths = False
        elif cur is not None and line.startswith("    paths:"):
            in_paths = True
        elif cur is not None and in_paths and line.lstrip().startswith("- "):
            val = line.lstrip()[2:].strip().strip('"').strip("'")
            cur["paths"].append(val)
        elif cur is not None and line.startswith("    severity_block:"):
            cur["severity_block"] = line.split(":", 1)[1].strip()
            in_paths = False
        elif cur is not None and not line.startswith("      "):
            in_paths = False
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

rules = parse_yaml(text)
compiled = [(r, [glob_to_re(p) for p in r.get("paths", [])]) for r in rules]

for path in (p.strip() for p in changed_list.splitlines() if p.strip()):
    for rule, regexes in compiled:
        if any(rx.match(path) for rx in regexes):
            print("{}\t{}\t{}".format(
                path, rule.get("id", "?"), rule.get("severity_block", "HIGH")))
            break
PY
)"

# -- 8) Bucket files by severity -------------------------------------------
critical_files=()
high_files=()
while IFS=$'\t' read -r path rule_id sev; do
    [[ -z "${path:-}" ]] && continue
    case "$sev" in
        CRITICAL) critical_files+=("$path") ;;
        *)        high_files+=("$path") ;;
    esac
done <<EOF
$classifications
EOF

# -- 9) Deterministic CRITICAL-pattern scan on critical_files --------------
violations=""
if [[ ${#critical_files[@]} -gt 0 ]]; then
    diff_text="$(git diff "$diff_range" -U0 -- "${critical_files[@]}" 2>/dev/null || true)"
    violations="$(DIFF_TEXT="$diff_text" python3 - <<'PY'
import os, re, sys

diff_text = os.environ.get("DIFF_TEXT", "")

CRITICAL_PATTERNS = [
    (re.compile(r'(^|[^A-Za-z_])unsafe\s*[\{\(]'),   "new `unsafe` block"),
    (re.compile(r'\.unwrap\(\)'),                    "new `.unwrap()`"),
    (re.compile(r'\.expect\('),                      "new `.expect()`"),
    (re.compile(r'\bpanic!\s*\('),                   "new `panic!()`"),
    (re.compile(r'\b(unimplemented|todo)!\s*\('),    "new `unimplemented!()` / `todo!()`"),
    (re.compile(r'Command::new\s*\(\s*"(sh|bash)"'), "raw shell `Command::new(\"sh|bash\")`"),
]

# -- Test-code exemption ----------------------------------------------------
# `.expect()` / `panic!()` / `.unwrap()` are idiomatic and correct in test
# code — it never executes on the host, so gating it is pure false-positive
# noise (observed 2026-06-02: 3 of 7 Layer-1 findings were test-code FPs).
# We exempt two cases: whole test files, and lines inside a `#[cfg(test)]`
# module or a `#[test]` / `#[<runtime>::test]` function within a prod file.
#
# Because the gate diffs with -U0 (no context), we cannot see the enclosing
# `#[cfg(test)]` attribute in the diff itself — so we read the file on disk
# and compute test-scope line ranges by brace-matching. Comments and
# double-quoted strings are stripped before counting braces so that braces
# inside string literals don't skew the depth. If a block's braces never
# balance we do NOT mark a range (bias toward flagging, never toward
# silently exempting a real prod expect).

def is_test_file(path):
    base = path.rsplit("/", 1)[-1]
    return base == "tests.rs" or base.endswith("_test.rs") or "/tests/" in path

def strip_braces_source(line):
    out = []
    i, n = 0, len(line)
    in_str = False
    while i < n:
        c = line[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break  # rest of line is a comment
        out.append(c)
        i += 1
    return "".join(out)

TEST_ATTR = re.compile(r'^#\[\s*(cfg\(\s*test\s*\)|test|[A-Za-z_][A-Za-z0-9_:]*::test)')

def compute_test_ranges(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    ranges = []
    n = len(lines)
    i = 0
    while i < n:
        if TEST_ATTR.match(lines[i].strip()):
            depth = 0
            started = False
            j = i
            while j < n:
                for ch in strip_braces_source(lines[j]):
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                if started and depth <= 0:
                    break
                j += 1
            if started and depth <= 0:
                ranges.append((i + 1, j + 1))  # 1-based inclusive
                i = j + 1
                continue
        i += 1
    return ranges

_range_cache = {}

def in_test_scope(path, ln):
    if is_test_file(path):
        return True
    if path not in _range_cache:
        _range_cache[path] = compute_test_ranges(path)
    return any(a <= ln <= b for a, b in _range_cache[path])

cur_file = None
new_ln = 0
hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

for raw in diff_text.splitlines():
    if raw.startswith("+++ b/"):
        cur_file = raw[6:]
        continue
    if raw.startswith("--- ") or raw.startswith("diff --git "):
        continue
    m = hunk_re.match(raw)
    if m:
        new_ln = int(m.group(1))
        continue
    if not raw.startswith("+") or raw.startswith("+++"):
        if raw.startswith(" "):
            new_ln += 1
        continue

    body = raw[1:]
    stripped = body.lstrip()
    if (stripped.startswith("//") or stripped.startswith("#[")
            or not stripped):
        new_ln += 1
        continue

    for rx, msg in CRITICAL_PATTERNS:
        if rx.search(body):
            if cur_file and not in_test_scope(cur_file, new_ln):
                print("{}:{}\t{}\t{}".format(cur_file, new_ln, msg, body.strip()[:120]))
            break
    new_ln += 1
PY
)"
fi

# -- 10) Run cargo fmt + clippy (deterministic gates) ----------------------
fmt_log="$(mktemp -t agg-precommit-fmt.XXXXXX)"
clippy_log="$(mktemp -t agg-precommit-clippy.XXXXXX)"
trap 'rm -f "$fmt_log" "$clippy_log"' EXIT

fmt_failed=0
clippy_failed=0
cargo_missing=0

if ! command -v cargo >/dev/null 2>&1; then
    cargo_missing=1
else
    cargo fmt --all -- --check >"$fmt_log" 2>&1 || fmt_failed=1
    cargo clippy --workspace --exclude agent-guard-python --all-features -- -D warnings \
        >"$clippy_log" 2>&1 || clippy_failed=1
fi

# -- 11) Report ------------------------------------------------------------
block=0
{
    echo "$LOG_PREFIX layer-2 gate report"
    echo "  diff scope:           git diff $diff_range"
    echo "  changed .rs files:    $(printf '%s\n' "$changed_rs_list" | wc -l | tr -d ' ')"
    echo "  CRITICAL-scoped:      ${#critical_files[@]}"
    echo "  HIGH-scoped:          ${#high_files[@]}"
    echo

    if [[ $cargo_missing -eq 1 ]]; then
        echo "  WARN: cargo not in PATH; fmt/clippy gates skipped"
    else
        if [[ $fmt_failed -eq 1 ]]; then
            echo "  CRITICAL: cargo fmt --check failed"
            sed 's/^/    | /' "$fmt_log" | head -20
            block=1
        fi
        if [[ $clippy_failed -eq 1 ]]; then
            echo "  CRITICAL: cargo clippy -D warnings failed"
            sed 's/^/    | /' "$clippy_log" | tail -40
            block=1
        fi
    fi

    if [[ -n "$violations" ]]; then
        v_count="$(printf '%s\n' "$violations" | grep -c . || true)"
        echo "  CRITICAL: $v_count pattern violation(s) in security-critical files:"
        printf '%s\n' "$violations" | sed 's/^/    - /'
        block=1
    fi

    echo
    if [[ $block -eq 1 ]]; then
        echo "$LOG_PREFIX BLOCK — fix CRITICAL findings above, then re-commit."
        echo "$LOG_PREFIX override (emergency only): AGENT_GUARD_SKIP_PRECOMMIT=1 git commit ..."
    else
        echo "$LOG_PREFIX PASS — clean diff; commit allowed."
    fi
} >&2

[[ $block -eq 1 ]] && exit 2
exit 0
