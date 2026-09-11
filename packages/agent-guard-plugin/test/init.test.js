'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  BINARIES,
  HOOK_ID,
  MATCHER,
  withHook,
  withoutHook,
  isAgentGuardEntry,
  policyWithFileAudit,
} = require('../lib/init.js');
const { hasExactVersion, installOne } = require('../bin/cli.js');
const PACKAGE_VERSION = require('../package.json').version;

const CMD = 'guard-hook check --policy /home/u/.claude/agent-guard/policy.yaml --agent-id claude-code';

test('withHook adds the gate to empty settings without losing the shape', () => {
  const out = withHook({}, CMD);
  const entries = out.hooks.PreToolUse;
  assert.equal(entries.length, 1);
  assert.equal(entries[0].id, HOOK_ID);
  assert.equal(entries[0].matcher, MATCHER);
  assert.equal(entries[0].hooks[0].command, CMD);
});

test('withHook preserves unrelated settings keys and other PreToolUse hooks', () => {
  const existing = {
    model: 'claude-opus-4-8',
    permissions: { allow: ['Bash(ls)'] },
    hooks: {
      PreToolUse: [
        { matcher: 'Bash', hooks: [{ type: 'command', command: 'other-tool' }] },
      ],
      PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'fmt' }] }],
    },
  };
  const out = withHook(existing, CMD);
  assert.equal(out.model, 'claude-opus-4-8');
  assert.deepEqual(out.permissions, existing.permissions);
  assert.deepEqual(out.hooks.PostToolUse, existing.hooks.PostToolUse);
  // The unrelated PreToolUse hook survives; ours is appended.
  assert.equal(out.hooks.PreToolUse.length, 2);
  assert.equal(out.hooks.PreToolUse[0].hooks[0].command, 'other-tool');
  assert.equal(out.hooks.PreToolUse[1].id, HOOK_ID);
});

test('withHook is idempotent and refreshes the command on re-run', () => {
  const once = withHook({}, CMD);
  const twice = withHook(once, 'guard-hook check --policy /new/path.yaml --agent-id x');
  const ours = twice.hooks.PreToolUse.filter(isAgentGuardEntry);
  assert.equal(ours.length, 1, 'exactly one agent-guard entry after re-run');
  assert.equal(ours[0].hooks[0].command, 'guard-hook check --policy /new/path.yaml --agent-id x');
});

test('withHook does not mutate the input settings', () => {
  const input = { hooks: { PreToolUse: [] } };
  const snapshot = JSON.stringify(input);
  withHook(input, CMD);
  assert.equal(JSON.stringify(input), snapshot);
});

test('withoutHook removes only the agent-guard entry', () => {
  const withOther = {
    hooks: {
      PreToolUse: [
        { matcher: 'Bash', hooks: [{ type: 'command', command: 'other-tool' }] },
      ],
    },
  };
  const installed = withHook(withOther, CMD);
  const removed = withoutHook(installed);
  assert.equal(removed.hooks.PreToolUse.length, 1);
  assert.equal(removed.hooks.PreToolUse[0].hooks[0].command, 'other-tool');
  assert.equal(removed.hooks.PreToolUse.filter(isAgentGuardEntry).length, 0);
});

test('withoutHook is a no-op when no agent-guard entry exists', () => {
  const settings = { hooks: { PreToolUse: [] } };
  assert.deepEqual(withoutHook(settings), settings);
});

test('policyWithFileAudit redirects stdout audit to a file path', () => {
  const preset = 'audit:\n  enabled: true\n  output: stdout\n  include_payload_hash: true\n';
  const out = policyWithFileAudit(preset, '/home/u/.claude/agent-guard/audit.jsonl');
  assert.match(out, /output: file/);
  assert.match(out, /file_path: "\/home\/u\/\.claude\/agent-guard\/audit\.jsonl"/);
  assert.doesNotMatch(out, /output: stdout/);
  // Surrounding lines are untouched.
  assert.match(out, /enabled: true/);
  assert.match(out, /include_payload_hash: true/);
});

test('policyWithFileAudit leaves a non-stdout preset unchanged', () => {
  const preset = 'audit:\n  enabled: true\n  output: file\n  file_path: "x"\n';
  assert.equal(policyWithFileAudit(preset, '/whatever'), preset);
});

test('bundled policy asset stays byte-identical to the repo outbound preset (no drift)', () => {
  const bundled = path.join(__dirname, '..', 'assets', 'coding-agent-outbound.yaml');
  const source = path.join(__dirname, '..', '..', '..', 'presets', 'coding-agent-outbound.yaml');
  assert.ok(fs.existsSync(bundled), 'bundled policy asset is present');
  assert.ok(fs.existsSync(source), 'repo preset is present');
  assert.equal(
    fs.readFileSync(bundled, 'utf8'),
    fs.readFileSync(source, 'utf8'),
    'bundled policy has drifted from presets/coding-agent-outbound.yaml — re-copy it'
  );
});

// The gate is Rust and the installer is Node, so "the plugin installs what the
// gate tells a human to run" is an invariant neither side can check alone.
// That is exactly how it broke: `init` installed guard-hook, the hook printed
// `agent-guard push …`, and the human ran it and got `command not found`.
test('the plugin installs every binary the hook tells a human to run', () => {
  const hintSource = fs.readFileSync(
    path.join(__dirname, '..', '..', '..', 'crates', 'guard-hook', 'src', 'broker_hint.rs'),
    'utf8',
  );

  const named = new Set(
    [...hintSource.matchAll(/([a-z][a-z0-9-]*) push --remote/g)].map((m) => m[1]),
  );
  assert.ok(named.size > 0, 'the hint must name at least one runnable command');

  const installed = new Set(BINARIES.map((b) => b.bin));
  for (const bin of named) {
    assert.ok(
      installed.has(bin),
      `the hook prints "${bin} push --remote …" but init does not install ${bin}`,
    );
  }
});

test('binary reuse requires the exact package version', () => {
  for (const bin of ['guard-hook', 'agent-guard']) {
    const run = (command) => ({
      status: 0,
      stdout: command === `/exact/${bin}`
        ? `${bin} ${PACKAGE_VERSION}\n`
        : `${bin} 0.0.0\n`,
    });
    assert.equal(hasExactVersion(`/exact/${bin}`, bin, PACKAGE_VERSION, run), true);
    assert.equal(hasExactVersion(`/old/${bin}`, bin, PACKAGE_VERSION, run), false);
  }
});

test('a stale PATH binary is replaced and the cargo binary is reverified', () => {
  let installed = false;
  let installArgs = null;
  const run = (command, args) => {
    if (command === '/path/guard-hook') {
      return { status: 0, stdout: 'guard-hook 0.2.2\n' };
    }
    if (command === '/cargo/bin/guard-hook') {
      return {
        status: installed ? 0 : 1,
        stdout: installed ? `guard-hook ${PACKAGE_VERSION}\n` : '',
      };
    }
    if (command === 'cargo' && args[0] === '--version') {
      return { status: 0, stdout: 'cargo 1.90.0\n' };
    }
    if (command === 'cargo' && args[0] === 'install') {
      installed = true;
      installArgs = args;
      return { status: 0, stdout: '' };
    }
    throw new Error(`unexpected command ${command}`);
  };

  const resolved = installOne(
    { crate: 'guard-hook', bin: 'guard-hook', why: 'test' },
    false,
    {
      resolveBinary: () => '/path/guard-hook',
      cargoBinaryPath: () => '/cargo/bin/guard-hook',
      spawnSync: run,
    },
  );

  assert.equal(resolved, '/cargo/bin/guard-hook');
  assert.ok(installArgs.includes('--force'));
  assert.deepEqual(
    installArgs.slice(0, 5),
    ['install', 'guard-hook', '--version', PACKAGE_VERSION, '--locked'],
  );
});
