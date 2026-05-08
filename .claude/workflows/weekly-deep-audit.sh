#!/usr/bin/env bash
#
# .claude/workflows/weekly-deep-audit.sh — Layer 3 weekly deep audit
#
# Fires three Claude Code reviewer agents in parallel against the
# security-critical surface and aggregates their findings into a single
# dated markdown report under docs/audits/.
#
#   - silent-failure-hunter  → SDK + validators + sandbox
#       (swallowed errors, bad fallbacks, missing error propagation)
#   - security-bounty-hunter → validators + sandbox + policy
#       (validator bypass, sandbox escape, signature/executor injection)
#   - type-design-analyzer   → GuardDecision / DecisionCode / TrustLevel
#       (invariant expression, illegal-state representability)
#
# Driven by a `schedule` skill routine (target: every Monday 09:00 local).
# Can also be run manually any time. Designed to fail open: if a single
# agent crashes, the other two still produce output.
#
# Usage:
#   .claude/workflows/weekly-deep-audit.sh                # all three agents
#   .claude/workflows/weekly-deep-audit.sh --dry-run      # print prompts only
#   .claude/workflows/weekly-deep-audit.sh --agent silent-failure
#   .claude/workflows/weekly-deep-audit.sh --agent security-bounty
#   .claude/workflows/weekly-deep-audit.sh --agent type-design
#
# Output: docs/audits/YYYY-MM-DD.md (suffix -2/-3/... if same-day re-run).
# Exit:   0 if every requested agent produced output, non-zero otherwise.

set -uo pipefail

LOG_PREFIX="[weekly-deep-audit]"

# -- 1) Args -----------------------------------------------------------------
DRY_RUN=0
ONLY_AGENT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)        DRY_RUN=1; shift ;;
        --agent)          ONLY_AGENT="${2:-}"; shift 2 ;;
        --help|-h)
            sed -n '1,/^set -uo pipefail/p' "$0" | sed -n 's/^# \{0,1\}//p'
            exit 0 ;;
        *) echo "$LOG_PREFIX unknown arg: $1" >&2; exit 64 ;;
    esac
done

case "${ONLY_AGENT:-}" in
    ""|silent-failure|security-bounty|type-design) ;;
    *) echo "$LOG_PREFIX --agent must be one of: silent-failure | security-bounty | type-design" >&2
       exit 64 ;;
esac

# -- 2) Anchor & output path -------------------------------------------------
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
    echo "$LOG_PREFIX must be run inside a git working tree" >&2
    exit 65
fi
cd "$REPO_ROOT"

DATE_TAG="$(date +%Y-%m-%d)"
OUT_DIR="$REPO_ROOT/docs/audits"
mkdir -p "$OUT_DIR"

OUT_FILE="$OUT_DIR/$DATE_TAG.md"
suffix=2
while [[ -e "$OUT_FILE" ]]; do
    OUT_FILE="$OUT_DIR/$DATE_TAG-$suffix.md"
    suffix=$((suffix + 1))
done

# -- 3) Per-agent prompts ----------------------------------------------------
# Each prompt is a self-contained brief: who you are, what to look at, what
# to ignore, what shape of output to return. The outer Claude session that
# `claude -p` spawns is expected to read "Use the X agent" and invoke the
# Task / Agent tool with subagent_type=X.

PROMPT_SILENT_FAILURE='Use the silent-failure-hunter agent to review the following modules of the agent-guard repository (you are inside the repository working tree):

- crates/agent-guard-sdk/src/
- crates/agent-guard-validators/src/
- crates/agent-guard-sandbox/src/

Look specifically for:
- `let _ = <expr returning Result>` swallowing errors
- `unwrap_or_default()` / `ok()` / `err()` masking real failures
- `if let Ok(x) = ... else {}` patterns that drop errors
- Errors logged but not returned at audit / policy / executor boundaries
- `?` removed in favor of fallback values without comment justification

Out of scope: style, performance, generic refactoring suggestions.

Return ONLY a markdown report to stdout, no preamble or trailing chatter. Format:

```
### Findings (silent-failure-hunter)

- **CRITICAL** path/to/file.rs:LINE — one-sentence finding
  remediation: one-sentence suggested fix
- **HIGH** ...
```

If you find nothing, write exactly: `_no findings_` and stop.'

PROMPT_SECURITY_BOUNTY='Use the security-bounty-hunter agent to scan the agent-guard repository for remotely reachable, exploitable issues. You are inside the repository working tree.

In-scope targets:
- crates/agent-guard-validators/src/ (bash + path validators)
- crates/agent-guard-sandbox/src/ (seccomp / Seatbelt / Windows Job impls)
- crates/agent-guard-core/src/policy.rs (rule matching, DSL eval)
- crates/agent-guard-sdk/src/policy_signing.rs (Ed25519 attestation)
- crates/agent-guard-sdk/src/executors.rs (HTTP / file / shell executor pipeline)

In-scope vulnerability classes: validator bypass, path traversal escape, sandbox escape, signature forge, policy DSL injection, executor SSRF / TOCTOU / argument injection.

Out of scope: theoretical-only findings, local-DoS, requires-physical-access, supply-chain.

Return ONLY a markdown report to stdout. For each finding:

```
### Findings (security-bounty-hunter)

- **CRITICAL** category — short title
  attacker input: <minimal example>
  reachability: <how an external caller triggers it>
  impact: <what the attacker gains>
  remediation: <one-sentence fix direction>
```

If you find nothing, write exactly: `_no findings_` and stop.'

PROMPT_TYPE_DESIGN='Use the type-design-analyzer agent to review the invariant expression and enforcement of these public types in the agent-guard repository (you are inside the repository working tree):

- `GuardDecision` (crates/agent-guard-core/src/decision.rs)
- `DecisionCode` (crates/agent-guard-core/src/decision.rs)
- `TrustLevel` (crates/agent-guard-core/src/types.rs)
- `PolicyMode` (locate via grep)

For each type, evaluate:
1. Are illegal states unrepresentable, or can a caller construct an inconsistent value?
2. Do derive macros (`Clone`, `Default`, `Deserialize`, ...) expose mutability or default-construction paths that bypass intended invariants?
3. Does the public API force callers through the right invariant-preserving constructors / methods?
4. Are there silent-coercion paths (`From` / `Into` / `as`) that downgrade trust or decision strength?

Out of scope: cosmetic naming, doc-comment polish.

Return ONLY a markdown report to stdout. Format:

```
### Findings (type-design-analyzer)

- **CRITICAL** TypeName — one-sentence invariant violation
  example: minimal Rust snippet that breaks the invariant
  remediation: one-sentence fix direction
```

If you find nothing, write exactly: `_no findings_` and stop.'

# -- 4) Agent dispatch -------------------------------------------------------
# Each agent runs in its own claude -p subprocess. Output is captured per
# agent into temp files; aggregated into the final report at the end.

TMPDIR_RUN="$(mktemp -d -t agg-weekly-audit.XXXXXX)"
trap 'rm -rf "$TMPDIR_RUN"' EXIT

run_one() {
    local short="$1" label="$2" prompt="$3"
    local out="$TMPDIR_RUN/$short.md"

    if [[ $DRY_RUN -eq 1 ]]; then
        {
            echo "## $label  _(DRY RUN)_"
            echo
            echo "Would invoke \`claude -p\` with this prompt:"
            echo
            echo '```'
            echo "$prompt"
            echo '```'
            echo
        } > "$out"
        return 0
    fi

    if ! command -v claude >/dev/null 2>&1; then
        {
            echo "## $label"
            echo
            echo "**\`claude\` CLI not in PATH; agent skipped.**"
            echo
        } > "$out"
        return 1
    fi

    {
        echo "## $label"
        echo
        # `claude -p` runs a single non-interactive Claude Code session. The
        # session reads our prompt, sees the "Use the <agent>" directive,
        # invokes that agent via Agent tool, and prints the agent'"'"'s
        # markdown report verbatim. Stdout streams into the section.
        if ! printf '%s\n' "$prompt" | claude -p 2>>"$TMPDIR_RUN/$short.err"; then
            echo
            echo "**Agent run returned non-zero. Stderr tail:**"
            echo
            echo '```'
            tail -40 "$TMPDIR_RUN/$short.err" 2>/dev/null
            echo '```'
        fi
        echo
    } > "$out"
}

declare -a pids
declare -a labels
declare -a shorts

queue() {
    local short="$1" label="$2" prompt_var="$3"
    if [[ -z "$ONLY_AGENT" || "$ONLY_AGENT" == "$short" ]]; then
        run_one "$short" "$label" "${!prompt_var}" &
        pids+=("$!")
        labels+=("$label")
        shorts+=("$short")
    fi
}

queue "silent-failure"   "silent-failure-hunter"   "PROMPT_SILENT_FAILURE"
queue "security-bounty"  "security-bounty-hunter"  "PROMPT_SECURITY_BOUNTY"
queue "type-design"      "type-design-analyzer"    "PROMPT_TYPE_DESIGN"

if [[ ${#pids[@]} -eq 0 ]]; then
    echo "$LOG_PREFIX no agents to run (check --agent value)" >&2
    exit 64
fi

# -- 5) Wait & track per-agent exit codes ------------------------------------
exit_code=0
declare -a status
for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
        status+=("ok")
    else
        status+=("fail")
        exit_code=1
        echo "$LOG_PREFIX ${shorts[$i]} returned non-zero" >&2
    fi
done

# -- 6) Aggregate ------------------------------------------------------------
{
    cat <<EOF
# Weekly deep audit — $DATE_TAG

Generated by \`.claude/workflows/weekly-deep-audit.sh\`.

| agent | scope | status |
| --- | --- | --- |
EOF
    for i in "${!shorts[@]}"; do
        case "${shorts[$i]}" in
            silent-failure)
                scope="SDK + validators + sandbox" ;;
            security-bounty)
                scope="validators + sandbox + policy + signing + executors" ;;
            type-design)
                scope="GuardDecision / DecisionCode / TrustLevel / PolicyMode" ;;
            *) scope="—" ;;
        esac
        echo "| ${labels[$i]} | $scope | ${status[$i]} |"
    done
    echo
    echo "Triage: convert any **CRITICAL** finding into a GitHub issue or fix PR before the next run."
    echo

    for sh in "${shorts[@]}"; do
        f="$TMPDIR_RUN/$sh.md"
        if [[ -f "$f" ]]; then
            cat "$f"
            echo
        fi
    done
} > "$OUT_FILE"

echo "$LOG_PREFIX wrote $OUT_FILE" >&2
exit $exit_code
