#!/usr/bin/env node
'use strict';

// agent-guard-plugin CLI — bootstraps the agent-guard outbound gate into a
// user's Claude Code install.
//
//   npx agent-guard-plugin init        full setup: binary + policy + hook
//   npx agent-guard-plugin init --binary-only   just install guard-hook
//   npx agent-guard-plugin uninstall   remove the hook from settings.json
//
// Binary delivery is via `cargo install` (Rust toolchain required) — the
// agreed S8-2 distribution mechanism. The CLI is fail-soft: if cargo is
// missing it prints manual instructions and still wires the (fail-open) hook,
// so a partial setup never leaves Claude Code blocked.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { HOOK_ID, withHook, withoutHook, policyWithFileAudit } = require('../lib/init.js');

const REPO_URL = 'https://github.com/XuebinMa/agent-guard';
const PKG = require('../package.json');

function log(msg) {
  process.stdout.write(`${msg}\n`);
}
function warn(msg) {
  process.stderr.write(`${msg}\n`);
}

function parseArgs(argv) {
  const opts = {
    command: argv[0] && !argv[0].startsWith('-') ? argv[0] : 'help',
    dryRun: false,
    force: false,
    binaryOnly: false,
    skipBinary: false,
    agentId: 'claude-code',
    settingsPath: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--dry-run') opts.dryRun = true;
    else if (a === '--force') opts.force = true;
    else if (a === '--binary-only') opts.binaryOnly = true;
    else if (a === '--skip-binary') opts.skipBinary = true;
    else if (a === '--agent-id') opts.agentId = argv[(i += 1)];
    else if (a === '--settings') opts.settingsPath = argv[(i += 1)];
    else if (a === '--help' || a === '-h') opts.command = 'help';
    else if (a === '--version' || a === '-v') opts.command = 'version';
  }
  return opts;
}

// Locate an executable `guard-hook`: PATH first, then the cargo bin dir.
function resolveBinary() {
  const isWin = process.platform === 'win32';
  const probe = spawnSync(isWin ? 'where' : 'command', isWin ? ['guard-hook'] : ['-v', 'guard-hook']);
  if (probe.status === 0 && probe.stdout) {
    const found = probe.stdout.toString().split(/\r?\n/)[0].trim();
    if (found) return found;
  }
  const cargoBin = path.join(os.homedir(), '.cargo', 'bin', `guard-hook${isWin ? '.exe' : ''}`);
  if (fs.existsSync(cargoBin)) return cargoBin;
  return null;
}

function installBinary(dryRun) {
  const existing = resolveBinary();
  if (existing) {
    log(`✓ guard-hook already installed: ${existing}`);
    return existing;
  }
  if (spawnSync('cargo', ['--version']).status !== 0) {
    warn('! cargo not found. Install Rust (https://rustup.rs) then run:');
    warn(`    cargo install --git ${REPO_URL} guard-hook`);
    warn('  (the hook fails open until the binary is present, so nothing is blocked meanwhile)');
    return null;
  }
  if (dryRun) {
    log(`[dry-run] would run: cargo install --git ${REPO_URL} guard-hook`);
    return 'guard-hook';
  }
  log('Installing guard-hook via cargo (this can take a few minutes)…');
  const r = spawnSync('cargo', ['install', '--git', REPO_URL, 'guard-hook'], { stdio: 'inherit' });
  if (r.status !== 0) {
    warn('! cargo install failed; install manually with:');
    warn(`    cargo install --git ${REPO_URL} guard-hook`);
    return null;
  }
  return resolveBinary() || 'guard-hook';
}

function readJsonFile(file) {
  if (!fs.existsSync(file)) return {};
  const raw = fs.readFileSync(file, 'utf8').trim();
  if (raw === '') return {};
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error(`refusing to touch malformed JSON at ${file}: ${e.message}`);
  }
}

function writeFilePretty(file, data, dryRun) {
  if (dryRun) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, data);
}

// Minimal shell quoting for the command string written into settings.json.
function quote(s) {
  return `"${String(s).replace(/(["\\$`])/g, '\\$1')}"`;
}

function cmdInit(opts) {
  const home = os.homedir();
  const agentGuardDir = path.join(home, '.claude', 'agent-guard');
  const policyPath = path.join(agentGuardDir, 'policy.yaml');
  const auditPath = path.join(agentGuardDir, 'audit.jsonl');
  const settingsPath = opts.settingsPath || path.join(home, '.claude', 'settings.json');

  const binPath = opts.skipBinary ? resolveBinary() || 'guard-hook' : installBinary(opts.dryRun);

  if (opts.binaryOnly) {
    log('');
    log('Binary-only setup done. Register the hook via the marketplace plugin:');
    log('    /plugin marketplace add XuebinMa/agent-guard');
    log('    /plugin install agent-guard@agent-guard');
    return;
  }

  // Policy: bundled outbound preset, audit redirected to a file so the hook's
  // stdout stays clean (it carries only the decision Claude Code reads).
  const presetText = fs.readFileSync(path.join(__dirname, '..', 'assets', 'coding-agent-outbound.yaml'), 'utf8');
  const policyText = policyWithFileAudit(presetText, auditPath);
  if (fs.existsSync(policyPath) && !opts.force) {
    log(`• policy exists, keeping it: ${policyPath} (use --force to overwrite)`);
  } else {
    writeFilePretty(policyPath, policyText, opts.dryRun);
    log(`${opts.dryRun ? '[dry-run] would write' : '✓ wrote'} policy: ${policyPath}`);
  }

  const command = `${quote(binPath || 'guard-hook')} check --policy ${quote(policyPath)} --agent-id ${quote(opts.agentId)}`;
  const settings = readJsonFile(settingsPath);
  const next = withHook(settings, command);
  writeFilePretty(settingsPath, `${JSON.stringify(next, null, 2)}\n`, opts.dryRun);
  log(`${opts.dryRun ? '[dry-run] would update' : '✓ updated'} settings: ${settingsPath}`);
  log(`    PreToolUse [${HOOK_ID}] → ${command}`);

  log('');
  log('Done. Restart Claude Code (or start a new session) to load the hook.');
  log('Disable for one session with:  AGENT_GUARD_HOOK=off claude');
}

function cmdUninstall(opts) {
  const home = os.homedir();
  const settingsPath = opts.settingsPath || path.join(home, '.claude', 'settings.json');
  const settings = readJsonFile(settingsPath);
  const next = withoutHook(settings);
  writeFilePretty(settingsPath, `${JSON.stringify(next, null, 2)}\n`, opts.dryRun);
  log(`${opts.dryRun ? '[dry-run] would remove' : '✓ removed'} the agent-guard hook from ${settingsPath}`);
  log('The policy file and guard-hook binary are left in place; remove them manually if desired.');
}

function help() {
  log(`agent-guard-plugin ${PKG.version}

Bootstrap the agent-guard outbound gate into Claude Code.

Usage:
  npx agent-guard-plugin init [options]          install binary + policy + PreToolUse hook
  npx agent-guard-plugin uninstall [--dry-run]   remove the hook from settings.json

Options:
  --dry-run         show changes without writing anything
  --force           overwrite an existing policy file
  --binary-only     only install the guard-hook binary (use with the marketplace plugin)
  --skip-binary     do not run cargo install (assume guard-hook is present)
  --agent-id <id>   audit agent id recorded by the hook (default: claude-code)
  --settings <path> target settings.json (default: ~/.claude/settings.json)
  -h, --help        show this help
  -v, --version     show version

Binary delivery uses 'cargo install' (Rust required). The hook fails open if
the binary is absent, so a partial install never blocks your agent.`);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  try {
    switch (opts.command) {
      case 'init':
        cmdInit(opts);
        break;
      case 'uninstall':
        cmdUninstall(opts);
        break;
      case 'version':
        log(PKG.version);
        break;
      default:
        help();
    }
  } catch (e) {
    warn(`agent-guard-plugin: ${e.message}`);
    process.exit(1);
  }
}

main();
