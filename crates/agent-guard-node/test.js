'use strict'

const assert = require('assert/strict')
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
    const missingWorkspaceDecision = writeGuard.decide(
      'write_file',
      JSON.stringify({ path: writeTarget, content: 'must not write' })
    )
    assert.equal(missingWorkspaceDecision.outcome, 'deny')

    const writeContext = { workingDirectory: writeRoot }
    const writeDecision = writeGuard.decide(
      'write_file',
      JSON.stringify({ path: writeTarget, content: 'hello from node' }),
      writeContext
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
      JSON.stringify({ path: writeTarget, content: 'hello from node' }),
      writeContext
    )
    assert.equal(writeOutcome.status || writeOutcome.outcome, 'executed')
    assert.equal(readFileSync(writeTarget, 'utf8'), 'hello from node')

    // The mutation HTTP executor pins and vets the resolved address, failing
    // closed on private / loopback targets (SSRF guard, see executors.rs
    // `is_always_blocked_ip`). `decide` is computed without connecting, so the
    // decision surface is assertable directly; an actual `run` against a
    // loopback address must be blocked rather than executed.
    const loopbackUrl = 'http://127.0.0.1:8080/publish'
    const httpDecision = guard.decide(
      'http_request',
      JSON.stringify({ method: 'POST', url: loopbackUrl, body: 'payload' })
    )
    assert.equal(httpDecision.outcome, 'execute')

    const httpReadDecision = guard.decide(
      'http_request',
      JSON.stringify({ method: 'GET', url: loopbackUrl })
    )
    assert.equal(httpReadDecision.outcome, 'handoff')

    // Running the mutation fails closed: the SSRF guard rejects the resolved
    // loopback address, so `guard.run` rejects instead of executing.
    await assert.rejects(
      async () =>
        guard.run(
          'http_request',
          JSON.stringify({ method: 'POST', url: loopbackUrl, body: 'payload' })
        ),
      /blocked address|execution failed/i
    )

    const deniedOutcome = await guard.execute('bash', normalizePayload('bash', 'rm -rf /'))
    assert.notEqual(deniedOutcome.status || deniedOutcome.outcome, 'executed')
    assert.ok(deniedOutcome.decision)

    // Explicit backend selection (issue #100): "none" always resolves and is
    // truthful; a known-but-inactive backend resolves truthfully to "none"
    // (this binding compiles no Linux sandbox feature); unknown names reject.
    const noneBackend = await guard.execute(
      'bash',
      normalizePayload('bash', 'echo backend'),
      undefined,
      'none'
    )
    assert.equal(noneBackend.status || noneBackend.outcome, 'executed')
    assert.equal(noneBackend.sandboxType || noneBackend.sandbox_type, 'none')

    // Default build (no sandbox feature): linux-seccomp truthfully resolves to
    // 'none'. The CI seccomp leg builds the addon with `--features seccomp`
    // and sets AGENT_GUARD_EXPECT_BACKEND=linux-seccomp, proving the same
    // request then yields real isolation through the binding.
    const expectedSeccompResolution = process.env.AGENT_GUARD_EXPECT_BACKEND || 'none'
    const seccompBackend = await guard.execute(
      'bash',
      normalizePayload('bash', 'echo backend'),
      undefined,
      'linux-seccomp'
    )
    assert.equal(
      seccompBackend.sandboxType || seccompBackend.sandbox_type,
      expectedSeccompResolution
    )

    await assert.rejects(
      async () =>
        guard.execute('bash', normalizePayload('bash', 'echo backend'), undefined, 'bogus-backend'),
      /unknown sandbox backend/i
    )

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

    // High-level adapters must preserve Context::default()'s untrusted
    // boundary. A trusted caller may opt into the per-tool full-access
    // override, but omitting trust must leave the read-only default in force.
    const trustDefaultGuard = Guard.fromYaml(`
version: 1
default_mode: read_only
tools:
  write_file:
    mode: full_access
audit:
  enabled: false
`)
    const trustDefaultInput = {
      path: join(writeRoot, 'omitted-trust-must-not-write.txt'),
      content: 'must not run',
    }
    const trustDefaultPayload = JSON.stringify(trustDefaultInput)
    assert.equal(
      trustDefaultGuard.check('write_file', trustDefaultPayload, {
        trustLevel: 'Untrusted',
      }).outcome,
      'deny'
    )
    assert.equal(
      trustDefaultGuard.check('write_file', trustDefaultPayload, {
        trustLevel: 'Trusted',
      }).outcome,
      'allow'
    )

    let omittedTrustHandlerCalls = 0
    const omittedTrustHandler = wrapOpenAITool(
      trustDefaultGuard,
      async () => {
        omittedTrustHandlerCalls += 1
        return 'should-not-run'
      },
      {
        tool: 'write_file',
        mode: 'check',
      }
    )

    await assert.rejects(
      async () => omittedTrustHandler(trustDefaultInput),
      (error) =>
        error instanceof AgentGuardDeniedError &&
        error.code === 'WriteInReadOnlyMode'
    )
    assert.equal(omittedTrustHandlerCalls, 0)

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

      const invalidCheck = invalidSignedGuard.check(
        'bash',
        normalizePayload('bash', 'echo signed-check')
      )
      assert.equal(invalidCheck.outcome, 'deny')
      assert.equal(invalidCheck.code, 'PolicyVerificationFailed')

      const invalidDecide = invalidSignedGuard.decide(
        'bash',
        normalizePayload('bash', 'echo signed-decide')
      )
      assert.equal(invalidDecide.outcome, 'deny')
      assert.equal(invalidDecide.code, 'PolicyVerificationFailed')

      const invalidExecute = await invalidSignedGuard.execute(
        'bash',
        normalizePayload('bash', 'echo signed-execute'),
        undefined,
        'none'
      )
      assert.equal(invalidExecute.status || invalidExecute.outcome, 'denied')
      assert.equal(invalidExecute.decision.code, 'PolicyVerificationFailed')

      const invalidRun = await invalidSignedGuard.run(
        'bash',
        normalizePayload('bash', 'echo signed-run'),
        undefined,
        'none'
      )
      assert.equal(invalidRun.status || invalidRun.outcome, 'denied')
      assert.equal(invalidRun.decision.code, 'PolicyVerificationFailed')

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
