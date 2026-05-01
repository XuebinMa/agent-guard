// Cross-language parity runner — Node side.
//
// Reads policy.yaml + scenarios.json, runs each scenario through
// guard.check and guard.decide, prints one JSONL line per scenario in the
// same shape the Rust + Python runners emit.
//
// Usage:
//   node tests/cross-language-parity/runners/runner.js \
//        tests/cross-language-parity/fixtures/policy.yaml \
//        tests/cross-language-parity/fixtures/scenarios.json

const fs = require('fs')
const path = require('path')

const native = require(path.resolve(__dirname, '../../../crates/agent-guard-node/index.js'))
const { Guard } = native

const trustLevelMap = {
  untrusted: 'Untrusted',
  trusted: 'Trusted',
  admin: 'Admin',
}

function buildContext(ctx) {
  if (!ctx) return undefined
  const out = {}
  if (ctx.trust_level !== undefined) {
    out.trustLevel = trustLevelMap[String(ctx.trust_level).toLowerCase()] || 'Untrusted'
  }
  if (ctx.agent_id !== undefined) out.agentId = ctx.agent_id
  if (ctx.session_id !== undefined) out.sessionId = ctx.session_id
  if (ctx.actor !== undefined) out.actor = ctx.actor
  if (ctx.working_directory !== undefined) out.workingDirectory = ctx.working_directory
  return out
}

function emit(scenario, guard) {
  const tool = scenario.tool
  const payload = JSON.stringify(scenario.payload)
  const ctx = buildContext(scenario.context)

  const decision = guard.check(tool, payload, ctx)
  const runtime = guard.decide(tool, payload, ctx)

  return {
    name: scenario.name,
    decision: decision.outcome,
    code: decision.code ?? null,
    runtime_decision: runtime.outcome,
    runtime_code: runtime.code ?? null,
  }
}

function main() {
  const args = process.argv.slice(2)
  if (args.length !== 2) {
    console.error('usage: runner.js <policy.yaml> <scenarios.json>')
    process.exit(2)
  }
  const [policyPath, scenariosPath] = args

  const yaml = fs.readFileSync(policyPath, 'utf-8')
  const guard = Guard.fromYaml(yaml)
  const scenarios = JSON.parse(fs.readFileSync(scenariosPath, 'utf-8'))

  for (const scenario of scenarios) {
    process.stdout.write(JSON.stringify(emit(scenario, guard)) + '\n')
  }
}

main()
