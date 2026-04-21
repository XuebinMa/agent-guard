'use strict'

const assert = require('assert/strict')
const http = require('http')
const { mkdtempSync, readFileSync } = require('fs')
const { tmpdir } = require('os')
const { join } = require('path')

let nodePackage
try {
  nodePackage = require('.')
} catch (error) {
  console.log(`Skipping native smoke tests: ${error.message}`)
  process.exit(0)
}

const {
  Guard,
  normalizePayload,
  wrapOpenAITool,
  AgentGuardDeniedError,
  AgentGuardAskRequiredError,
} = nodePackage

const yaml = `
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - "echo"
      - "pwd"
    deny:
      - "rm -rf /"
`

async function runTest() {
  try {
    const guard = Guard.fromYaml(yaml)
    if (typeof guard.policyVerification === 'function') {
      assert.equal(guard.policyVerification().status, 'unsigned')
    }
    if (typeof guard.setSigningKey === 'function') {
      guard.setSigningKey('0000000000000000000000000000000000000000000000000000000000000001')
    }

    const decision = guard.check('bash', normalizePayload('bash', 'echo smoke'))
    assert.equal(decision.outcome, 'allow')
    if (decision.policyVerificationStatus) {
      assert.equal(decision.policyVerificationStatus, 'unsigned')
    }
    if (decision.policyVersion || decision.policy_version) {
      assert.ok(decision.policyVersion || decision.policy_version)
    }

    const runtimeDecision = guard.decide('bash', normalizePayload('bash', 'echo smoke'))
    assert.equal(runtimeDecision.outcome, 'execute')

    const runtimeHandoffDecision = guard.decide(
      'read_file',
      JSON.stringify({ path: '/workspace/README.md' })
    )
    assert.equal(runtimeHandoffDecision.outcome, 'handoff')

    const writeRoot = mkdtempSync(join(tmpdir(), 'agent-guard-node-'))
    const writeTarget = join(writeRoot, 'runtime-write.txt')
    const writePolicy = `
version: 1
default_mode: workspace_write
tools:
  write_file:
    allow_paths:
      - "${writeRoot}/**"
`
    const writeGuard = Guard.fromYaml(writePolicy)
    const writeDecision = writeGuard.decide(
      'write_file',
      JSON.stringify({ path: writeTarget, content: 'hello from node' })
    )
    assert.equal(writeDecision.outcome, 'execute')

    const executed = await guard.execute('bash', normalizePayload('bash', 'echo smoke'))
    assert.equal(executed.status || executed.outcome, 'executed')
    assert.ok(executed.output)
    assert.ok(executed.output.stdout.includes('smoke'))
    if (executed.policyVerificationStatus) {
      assert.equal(executed.policyVerificationStatus, 'unsigned')
    }
    if (executed.sandboxType || executed.sandbox_type) {
      assert.ok(executed.sandboxType || executed.sandbox_type)
    }
    if (executed.receipt) {
      assert.ok(executed.receipt)
    }

    const runtimeExecuted = await guard.run('bash', normalizePayload('bash', 'echo smoke'))
    assert.equal(runtimeExecuted.status || runtimeExecuted.outcome, 'executed')
    assert.ok(runtimeExecuted.output)
    assert.ok(runtimeExecuted.output.stdout.includes('smoke'))

    const runtimeHandoff = await guard.run(
      'read_file',
      JSON.stringify({ path: '/workspace/README.md' })
    )
    assert.equal(runtimeHandoff.status || runtimeHandoff.outcome, 'handoff')
    assert.ok(runtimeHandoff.decision)
    assert.ok(
      typeof runtimeHandoff.requestId === 'string' && runtimeHandoff.requestId.length > 0,
      'handoff outcome should expose a non-empty requestId'
    )

    // Round-trip the handoff result back into the audit stream. This does
    // not throw and is exercised here mainly for type-surface compatibility;
    // deeper audit-content assertions live in the Rust integration tests.
    guard.reportHandoffResult(runtimeHandoff.requestId, {
      exitCode: 0,
      durationMs: 12,
    })
    guard.reportHandoffResult(runtimeHandoff.requestId, {
      exitCode: 1,
      durationMs: 5,
      stderr: 'handoff stderr',
    })

    const writeOutcome = await writeGuard.run(
      'write_file',
      JSON.stringify({ path: writeTarget, content: 'hello from node' })
    )
    assert.equal(writeOutcome.status || writeOutcome.outcome, 'executed')
    assert.equal(readFileSync(writeTarget, 'utf8'), 'hello from node')

    let receivedBody = ''
    const server = http.createServer((req, res) => {
      let chunks = ''
      req.on('data', (chunk) => {
        chunks += chunk
      })
      req.on('end', () => {
        receivedBody = chunks
        res.statusCode = 202
        res.end('accepted')
      })
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    const httpUrl = `http://127.0.0.1:${address.port}/publish`
    const httpDecision = guard.decide(
      'http_request',
      JSON.stringify({ method: 'POST', url: httpUrl, body: 'payload' })
    )
    assert.equal(httpDecision.outcome, 'execute')

    const httpReadDecision = guard.decide(
      'http_request',
      JSON.stringify({ method: 'GET', url: httpUrl })
    )
    assert.equal(httpReadDecision.outcome, 'handoff')

    const httpOutcome = await guard.run(
      'http_request',
      JSON.stringify({ method: 'POST', url: httpUrl, body: 'payload' })
    )
    assert.equal(httpOutcome.status || httpOutcome.outcome, 'executed')
    assert.equal(httpOutcome.output.stdout, 'accepted')
    assert.equal(receivedBody, 'payload')
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    )

    const deniedOutcome = await guard.execute('bash', normalizePayload('bash', 'rm -rf /'))
    assert.notEqual(deniedOutcome.status || deniedOutcome.outcome, 'executed')
    assert.ok(deniedOutcome.decision)

    const enforcedHandler = wrapOpenAITool(
      guard,
      async () => {
        throw new Error('original handler should not run in enforce mode')
      },
      {
        tool: 'bash',
        mode: 'enforce',
        resultMapper: (outcome) => outcome.output?.stdout.trim() ?? '',
      }
    )

    const checkHandler = wrapOpenAITool(
      guard,
      async (input) => `ORIGINAL:${input}`,
      {
        tool: 'bash',
        mode: 'check',
      }
    )

    const enforced = await enforcedHandler('echo wrapped')
    assert.equal(enforced, 'wrapped')

    const checked = await checkHandler('echo via-original')
    assert.equal(checked, 'ORIGINAL:echo via-original')

    const deniedHandler = wrapOpenAITool(
      guard,
      async () => 'should-not-run',
      {
        tool: 'bash',
        mode: 'check',
      }
    )

    let blockedError
    try {
      await deniedHandler('rm -rf /')
    } catch (error) {
      blockedError = error
    }

    assert.ok(blockedError)
    assert.ok(
      blockedError instanceof AgentGuardDeniedError ||
        blockedError instanceof AgentGuardAskRequiredError
    )
    assert.ok(blockedError.decision === 'deny' || blockedError.decision === 'ask_user')
    assert.ok(blockedError.status === 'denied' || blockedError.status === 'ask_required')
    if (blockedError.policyVersion) {
      assert.ok(blockedError.policyVersion)
    }

    if (typeof Guard.fromSignedYaml === 'function') {
      const invalidSignedGuard = Guard.fromSignedYaml(
        yaml,
        '0000000000000000000000000000000000000000000000000000000000000001',
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      )
      assert.equal(invalidSignedGuard.policyVerification().status, 'invalid')

      const autoHandler = wrapOpenAITool(
        invalidSignedGuard,
        async () => 'should-not-run',
        {
          tool: 'bash',
          mode: 'auto',
        }
      )

      await assert.rejects(
        async () => autoHandler('echo signed'),
        (error) => error instanceof AgentGuardDeniedError && error.code === 'PolicyVerificationFailed'
      )
    }

    console.log('Node native smoke tests passed.')
  } catch (error) {
    console.error('Test failed:', error)
    process.exit(1)
  }
}

runTest()
