#!/usr/bin/env bash
# agent-guard Claude Code plugin — PreToolUse hook wrapper.
# ---------------------------------------------------------------------------
# Bridges Claude Code's PreToolUse event to the `guard-hook` binary: resolves
# the binary and the policy file, then streams the event through unchanged.
#
# Design contract (mirrors guard-hook's own, do not relax):
#   - FAIL OPEN. On any resolution failure (kill switch, missing binary,
#     missing policy) emit an `allow` decision so a broken or partial install
#     never blocks the user's agent.
#   - Exit code is always 0. The decision lives in the JSON body on stdout.
#   - Honour AGENT_GUARD_HOOK=off as a hard kill switch, checked first.
# ---------------------------------------------------------------------------
set -u

APPROVE='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":""}}'

emit_approve() {
  printf '%s\n' "$APPROVE"
  exit 0
}

# Hard kill switch — matches the binary's own AGENT_GUARD_HOOK=off contract.
[ "${AGENT_GUARD_HOOK:-}" = "off" ] && emit_approve

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Resolve the policy: explicit override wins, else the bundled outbound preset.
POLICY="${AGENT_GUARD_POLICY:-$PLUGIN_ROOT/presets/coding-agent-outbound.yaml}"
if [ ! -f "$POLICY" ]; then
  echo "guard-hook-plugin: policy not found at $POLICY; approving" >&2
  emit_approve
fi

# Resolve the binary: PATH first, then the common cargo install dir, then a
# binary the plugin install step (S8-2) may have dropped under bin/.
resolve_bin() {
  if command -v guard-hook >/dev/null 2>&1; then
    command -v guard-hook
    return 0
  fi
  for cand in "$HOME/.cargo/bin/guard-hook" "$PLUGIN_ROOT/bin/guard-hook"; do
    if [ -x "$cand" ]; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  return 1
}

if ! BIN="$(resolve_bin)"; then
  echo "guard-hook-plugin: guard-hook binary not found (install with 'cargo install --path crates/guard-hook' or 'npx agent-guard-plugin init'); approving" >&2
  emit_approve
fi

AGENT_ID="${AGENT_GUARD_AGENT_ID:-claude-code-plugin}"

# guard-hook prints any audit record(s) first, then exactly one hook-decision
# JSON line last. Claude Code reads the decision from stdout, so stdout must
# carry ONLY that final line. Capture the output and split it: preceding audit
# lines go to stderr (the diagnostic channel — preserved, not corrupting the
# decision); the last line is the decision. With a file-audit policy
# (`audit: { output: file }`) the SDK writes audit to its own file and stdout
# already holds only the decision, so this split is a harmless no-op.
RESPONSE="$("$BIN" check --policy "$POLICY" --agent-id "$AGENT_ID")"
STATUS=$?

if [ "$STATUS" -ne 0 ] || [ -z "$RESPONSE" ]; then
  # guard-hook is contracted to always exit 0 with a JSON body; treat any
  # deviation as a fault and fail open.
  echo "guard-hook-plugin: guard-hook exited $STATUS with empty output; approving" >&2
  emit_approve
fi

if [ "$(printf '%s\n' "$RESPONSE" | wc -l)" -gt 1 ]; then
  printf '%s\n' "$RESPONSE" | sed '$d' >&2
fi
printf '%s\n' "$RESPONSE" | tail -n 1
