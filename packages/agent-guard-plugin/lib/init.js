'use strict';

// Pure, side-effect-free helpers for `agent-guard-plugin init`.
// Kept separate from bin/cli.js so the settings-merge and policy-transform
// logic can be unit-tested without touching the filesystem, cargo, or network.
//
// Immutability: every function returns a new value and never mutates its
// inputs, so re-running init is predictable and the caller owns persistence.

// Stable identifier for the hook entry agent-guard writes into settings.json.
// Used to make init idempotent: a re-run replaces this entry rather than
// appending a duplicate, and uninstall removes exactly this entry.
const HOOK_ID = 'pre:agent-guard:outbound-gate';

// Claude Code tools that guard-hook maps to an agent-guard Tool. Anything else
// (e.g. Read) is approved without evaluation, so there is no point matching it.
const MATCHER = 'Bash|Write|Edit|WebFetch';

const HOOK_TIMEOUT_SECONDS = 10;

// Build the single PreToolUse hook entry. `command` is the full shell command
// Claude Code runs for each matched tool call.
function buildHookEntry(command) {
  return {
    matcher: MATCHER,
    hooks: [{ type: 'command', command, timeout: HOOK_TIMEOUT_SECONDS }],
    id: HOOK_ID,
  };
}

// True when a PreToolUse group is agent-guard's, by id or by a command that
// still carries our marker (covers settings written before `id` was honoured).
function isAgentGuardEntry(entry) {
  if (!entry || typeof entry !== 'object') return false;
  if (entry.id === HOOK_ID) return true;
  const hooks = Array.isArray(entry.hooks) ? entry.hooks : [];
  return hooks.some(
    (h) => h && typeof h.command === 'string' && h.command.includes(HOOK_ID)
  );
}

// Return a clone of settings with agent-guard's PreToolUse entry present
// exactly once and pointing at `command`. Existing unrelated hooks and every
// other settings key are preserved untouched. Idempotent.
function withHook(settings, command) {
  const next = settings && typeof settings === 'object' ? { ...settings } : {};
  const hooks = next.hooks && typeof next.hooks === 'object' ? { ...next.hooks } : {};
  const preToolUse = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];

  const others = preToolUse.filter((entry) => !isAgentGuardEntry(entry));
  hooks.PreToolUse = [...others, buildHookEntry(command)];
  next.hooks = hooks;
  return next;
}

// Return settings with agent-guard's PreToolUse entry removed. Leaves an empty
// PreToolUse array / hooks object in place rather than guessing whether the
// user wants those keys deleted.
function withoutHook(settings) {
  if (!settings || typeof settings !== 'object') return {};
  const next = { ...settings };
  if (!next.hooks || typeof next.hooks !== 'object') return next;
  const hooks = { ...next.hooks };
  if (Array.isArray(hooks.PreToolUse)) {
    hooks.PreToolUse = hooks.PreToolUse.filter((entry) => !isAgentGuardEntry(entry));
  }
  next.hooks = hooks;
  return next;
}

// Transform the bundled outbound preset so audit records go to a file instead
// of stdout. A Claude Code hook reads its decision from stdout, so audit on
// stdout would corrupt that channel; routing to a file keeps stdout clean and
// gives durable forensic storage. Operates on the single `output: stdout` line
// the preset ships with; if it is absent (already file-based) the text is
// returned unchanged so a user-edited preset keeps its own audit routing.
//
// The path is written as a JSON string, which is also a YAML double-quoted
// scalar with the same value. Interpolated raw, a Windows home directory
// (`C:\Users\…`) is an invalid `\U` escape: the policy stops parsing, and a
// hook that cannot load its policy approves everything.
function policyWithFileAudit(presetText, auditFilePath) {
  const fileBlock = `output: file\n  file_path: ${JSON.stringify(auditFilePath)}`;
  // A replacer function, so `$&` or `$1` in the path is text and not a pattern.
  // Spaces and tabs only: `\s` also matches the line break after the value.
  return presetText.replace(
    /^([ \t]*)output:[ \t]*stdout[ \t]*$/m,
    (_line, indent) => `${indent}${fileBlock}`
  );
}

// The binaries `init` installs, and why each one has to be there.
//
// `guard-hook` alone is not enough. When the gate stops a push it names
// `agent-guard push` as the way to perform it properly, so shipping the gate
// without the command it names leaves a human at a `command not found` — the
// dead end the hint exists to remove, moved one step further out.
const BINARIES = [
  { crate: 'guard-hook', bin: 'guard-hook', why: 'the PreToolUse gate' },
  { crate: 'agent-guard-cli', bin: 'agent-guard', why: 'the broker path the gate names' },
];

module.exports = {
  BINARIES,
  HOOK_ID,
  MATCHER,
  buildHookEntry,
  isAgentGuardEntry,
  withHook,
  withoutHook,
  policyWithFileAudit,
};
