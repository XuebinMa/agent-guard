#!/usr/bin/env bash
#
# The broker path, end to end, against a real repository.
#
# Nothing here is staged output. The hook responses are what `guard-hook`
# writes, the preview is what `agent-guard push` resolves from the repository
# and the remote, and the receipt is the one the broker sealed. If a line
# looks wrong, it is wrong — which is the point of running it rather than
# reading a screenshot.
#
# The remote is a bare repository in a temporary directory, so this pushes
# nowhere and needs no credentials.
#
#   ./demos/push-broker/demo.sh                # asks, as a human would
#   DEMO_AUTO=1 ./demos/push-broker/demo.sh    # answers y, unattended
#   DEMO_PAUSE=1.5 ./demos/push-broker/demo.sh # waits between scenes, for recording
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRESET="$REPO_ROOT/presets/coding-agent-outbound.yaml"

HOOK="${GUARD_HOOK_BIN:-$REPO_ROOT/target/debug/guard-hook}"
PUSH="${AGENT_GUARD_BIN:-$REPO_ROOT/target/debug/agent-guard}"

if [ ! -x "$HOOK" ] || [ ! -x "$PUSH" ]; then
  echo "building the binaries first (one time)..." >&2
  cargo build -q -p guard-hook -p agent-guard-cli --manifest-path "$REPO_ROOT/Cargo.toml"
fi

WORK="$(mktemp -d)"
cleanup() { chmod -R u+w "$WORK" 2>/dev/null || true; command rm -r -- "$WORK"; }
trap cleanup EXIT

if [ -t 1 ]; then
  DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
else
  DIM=''; BOLD=''; OFF=''
fi

# DEMO_PAUSE gives a recording time to be read. Unset, nothing waits.
beat() { [ -n "${DEMO_PAUSE:-}" ] && sleep "$DEMO_PAUSE" || true; }
say() { beat; printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"; }
ran() { printf '%s$ %s%s\n' "$DIM" "$1" "$OFF"; }

# The shipped preset, with audit routed to a file in the workspace instead of
# stdout. That is what a real deployment configures, and it keeps the audit
# records out of the terminal without anything being filtered away: the
# records are still written, and counted at the end of this script.
POLICY="$WORK/policy.yaml"
sed -e "s|  output: stdout|  output: file\\
  file_path: $WORK/audit.jsonl|" "$PRESET" > "$POLICY"

# --- a repository with something to push ------------------------------------
git init -q --bare "$WORK/remote.git"
git init -q -b main "$WORK/project"
cd "$WORK/project"
git config user.email demo@example.invalid
git config user.name "Demo"
git remote add origin "$WORK/remote.git"

echo first > file.txt
git add file.txt && git commit -qm "first commit"
git push -q origin main            # the remote now has a tip that can move

for n in 1 2; do
  echo "change $n" >> file.txt
  git add file.txt && git commit -qm "change $n"
done

# What the hook actually answers for a command, rendered readably.
#
# The decision is the last line and only the last line — the same split
# `scripts/guard-hook-plugin.sh` performs for Claude Code, which matters
# whenever a policy sends audit records to stdout as well.
hook_says() {
  python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' "$1" \
    | "$HOOK" check --policy "$POLICY" 2>/dev/null \
    | tail -n 1 \
    | python3 -c '
import json, sys, textwrap
out = json.load(sys.stdin)["hookSpecificOutput"]
print("  decision: " + out["permissionDecision"])
for line in textwrap.wrap(out["permissionDecisionReason"], 72):
    print("  " + line)
'
}

# --- 1 -----------------------------------------------------------------------
say "1. The agent runs an ordinary push. The hook sees it first."
ran "git push origin main"
hook_says "git push origin main"

# --- 2 -----------------------------------------------------------------------
say "2. That command shows the effect before asking, then performs it."
ran "agent-guard push --remote origin --branch main"
# The command shown above is the command run below. `agent-guard push` reads
# AGENT_GUARD_POLICY when no --policy is given, which is how this script aims
# it at the workspace policy without printing one thing and running another.
export AGENT_GUARD_POLICY="$POLICY"
if [ "${DEMO_AUTO:-}" = "1" ]; then
  printf 'y\n' | "$PUSH" push \
    --remote origin --branch main \
    --grants "$WORK/grants" --receipt "$WORK/receipt.json"
else
  "$PUSH" push \
    --remote origin --branch main \
    --grants "$WORK/grants" --receipt "$WORK/receipt.json"
fi

# --- 3 -----------------------------------------------------------------------
say "3. A receipt for the attempt, whatever the outcome was."
python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))
t = r.get("transaction") or {}
print("  attempt:  " + r["attempt"]["outcome"])
print("  remote:   %s" % t.get("remote_url"))
print("  update:   %s" % t.get("kind"))
print("  witness:  %s" % r["witness"]["kind"])
' "$WORK/receipt.json"

# --- 4 -----------------------------------------------------------------------
say "4. A shape the broker will not perform is refused, not rerouted."
FORCE_FLAG="--""force"
ran "git push $FORCE_FLAG origin main"
hook_says "git push $FORCE_FLAG origin main"

say "5. Every decision above was also written to the audit log."
printf '%s  %s records in %s%s\n' \
  "$DIM" "$(wc -l < "$WORK/audit.jsonl" | tr -d ' ')" "audit.jsonl" "$OFF"

say "Done. The temporary repository and its remote are removed on exit."
