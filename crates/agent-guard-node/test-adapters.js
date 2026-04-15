'use strict'

const assert = require('assert/strict')
const {
  createAdapterExports,
  AgentGuardDeniedError,
  AgentGuardAskRequiredError,
  AgentGuardExecutionError,
} = require('./adapters.js')

const adapterApi = createAdapterExports({
  normalizePayload(tool, rawInput) {
    if (tool === 'bash' || tool === 'shell' || tool === 'terminal') {
      return JSON.stringify({ command: rawInput })
    }
    return JSON.stringify({ input: rawInput })
  },
})

const {
  createGuardedExecutor,
  wrapLangChainTool,
  wrapOpenAITool,
} = adapterApi

function createMockGuard({ decision, executeOutcome, onCheck, onExecute }) {
  return {
    check(tool, payload, context) {
      if (typeof onCheck === 'function') {
        onCheck(tool, payload, context)
      }
      return decision
    },
    async execute(tool, payload, context) {
      if (typeof onExecute === 'function') {
        onExecute(tool, payload, context)
      }
      return executeOutcome
    },
  }
}

async function expectRejects(factory, ErrorType, predicate) {
  let error
  try {
    await factory()
  } catch (caught) {
    error = caught
  }

  assert.ok(error, 'expected promise to reject')
  assert.ok(error instanceof ErrorType, `expected ${ErrorType.name}, got ${error}`)
  if (predicate) {
    predicate(error)
  }
}

async function testCreateGuardedExecutorCheckAllow() {
  let handlerCalls = 0
  const guard = createMockGuard({
    decision: { outcome: 'allow', policyVersion: 'policy-check-allow' },
  })

  const guarded = createGuardedExecutor(guard, {
    mode: 'check',
    tool: 'calculator',
  })(async (input) => {
    handlerCalls += 1
    return { ok: true, input }
  })

  const result = await guarded({ expression: '2+2' })
  assert.equal(handlerCalls, 1)
  assert.deepEqual(result, { ok: true, input: { expression: '2+2' } })
}

async function testCreateGuardedExecutorCheckDeny() {
  let handlerCalls = 0
  const guard = createMockGuard({
    decision: {
      outcome: 'deny',
      message: 'blocked',
      code: 'DeniedByRule',
      matchedRule: 'bash.deny[0]',
      policyVersion: 'policy-check-deny',
    },
  })

  const guarded = createGuardedExecutor(guard, {
    mode: 'check',
    tool: 'bash',
  })(async () => {
    handlerCalls += 1
    return 'should-not-run'
  })

  await expectRejects(
    () => guarded('rm -rf /'),
    AgentGuardDeniedError,
    (error) => {
      assert.equal(handlerCalls, 0)
      assert.equal(error.decision, 'deny')
      assert.equal(error.policyVersion, 'policy-check-deny')
      assert.equal(error.status, 'denied')
    }
  )
}

async function testCreateGuardedExecutorCheckAsk() {
  let handlerCalls = 0
  const guard = createMockGuard({
    decision: {
      outcome: 'ask_user',
      message: 'requires approval',
      askPrompt: 'Approve git push?',
      code: 'DestructiveCommand',
      policyVersion: 'policy-check-ask',
    },
  })

  const guarded = createGuardedExecutor(guard, {
    mode: 'check',
    tool: 'bash',
  })(async () => {
    handlerCalls += 1
    return 'should-not-run'
  })

  await expectRejects(
    () => guarded('git push origin main'),
    AgentGuardAskRequiredError,
    (error) => {
      assert.equal(handlerCalls, 0)
      assert.equal(error.decision, 'ask_user')
      assert.equal(error.policyVersion, 'policy-check-ask')
      assert.equal(error.status, 'ask_required')
    }
  )
}

async function testCreateGuardedExecutorEnforceExecutedAndMapped() {
  const rawOutcome = {
    status: 'executed',
    output: { exitCode: 0, stdout: 'hello\n', stderr: '' },
    policyVersion: 'policy-enforce-executed',
    sandboxType: 'seccomp',
    receipt: 'signed-receipt',
  }

  const guard = createMockGuard({
    executeOutcome: rawOutcome,
  })

  const guardedRaw = createGuardedExecutor(guard, {
    mode: 'enforce',
    tool: 'bash',
  })(async () => 'unused')

  const guardedMapped = createGuardedExecutor(guard, {
    mode: 'enforce',
    tool: 'bash',
    resultMapper(outcome, originalInput) {
      return `${originalInput}:${outcome.output.stdout.trim()}`
    },
  })(async () => 'unused')

  const rawResult = await guardedRaw('echo hello')
  const mappedResult = await guardedMapped('echo hello')

  assert.deepEqual(rawResult, rawOutcome)
  assert.equal(mappedResult, 'echo hello:hello')
}

async function testCreateGuardedExecutorEnforceFailures() {
  const deniedGuard = createMockGuard({
    executeOutcome: {
      status: 'denied',
      decision: {
        outcome: 'deny',
        message: 'blocked',
        policyVersion: 'policy-enforce-deny',
      },
      policyVersion: 'policy-enforce-deny',
      sandboxType: 'seccomp',
    },
  })

  const askGuard = createMockGuard({
    executeOutcome: {
      status: 'ask_required',
      decision: {
        outcome: 'ask_user',
        message: 'approval required',
        policyVersion: 'policy-enforce-ask',
      },
      policyVersion: 'policy-enforce-ask',
      sandboxType: 'seccomp',
    },
  })

  await expectRejects(
    () => createGuardedExecutor(deniedGuard, { mode: 'enforce', tool: 'bash' })(async () => 'unused')('rm -rf /'),
    AgentGuardDeniedError,
    (error) => {
      assert.equal(error.policyVersion, 'policy-enforce-deny')
      assert.equal(error.sandboxType, 'seccomp')
    }
  )

  await expectRejects(
    () => createGuardedExecutor(askGuard, { mode: 'enforce', tool: 'bash' })(async () => 'unused')('git push'),
    AgentGuardAskRequiredError,
    (error) => {
      assert.equal(error.policyVersion, 'policy-enforce-ask')
      assert.equal(error.sandboxType, 'seccomp')
    }
  )
}

async function testCreateGuardedExecutorAutoMode() {
  let handlerCalls = 0
  const allowGuard = createMockGuard({
    decision: { outcome: 'allow', policyVersion: 'policy-auto-allow' },
  })
  const denyGuard = createMockGuard({
    decision: { outcome: 'deny', message: 'blocked', policyVersion: 'policy-auto-deny' },
  })

  const guardedAllow = createGuardedExecutor(allowGuard, {
    mode: 'auto',
    tool: 'web_search',
  })(async (input) => {
    handlerCalls += 1
    return { ok: true, input }
  })

  const guardedDeny = createGuardedExecutor(denyGuard, {
    mode: 'auto',
    tool: 'web_search',
  })(async () => {
    handlerCalls += 1
    return 'should-not-run'
  })

  const result = await guardedAllow({ query: 'agent guard' })
  assert.equal(handlerCalls, 1)
  assert.deepEqual(result, { ok: true, input: { query: 'agent guard' } })

  await expectRejects(
    () => guardedDeny({ query: 'blocked' }),
    AgentGuardDeniedError,
    () => {
      assert.equal(handlerCalls, 1)
    }
  )
}

async function testCreateGuardedExecutorAutoFailsClosedOnInvalidPolicyVerification() {
  let handlerCalls = 0
  const invalidGuard = createMockGuard({
    decision: {
      outcome: 'allow',
      policyVersion: 'policy-auto-invalid',
      policyVerificationStatus: 'invalid',
      policyVerificationError: 'signature verification failed',
    },
  })

  const guarded = createGuardedExecutor(invalidGuard, {
    mode: 'auto',
    tool: 'web_search',
  })(async () => {
    handlerCalls += 1
    return 'should-not-run'
  })

  await expectRejects(
    () => guarded({ query: 'guard' }),
    AgentGuardDeniedError,
    (error) => {
      assert.equal(handlerCalls, 0)
      assert.equal(error.code, 'PolicyVerificationFailed')
    }
  )
}

async function testLangChainWrapperCompatibility() {
  const payloads = []
  let invokeCalls = 0
  let callCalls = 0
  let privateCalls = 0
  const guard = createMockGuard({
    decision: { outcome: 'allow', policyVersion: 'policy-langchain' },
    onCheck(tool, payload) {
      payloads.push({ tool, payload })
    },
  })

  const tool = {
    name: 'calculator',
    description: 'test tool',
    metadata: { version: 1 },
    async invoke(input) {
      invokeCalls += 1
      return `invoke:${input.expression}`
    },
    async call(input) {
      callCalls += 1
      return `call:${input.expression}`
    },
    async _call(input) {
      privateCalls += 1
      return `_call:${input.expression}`
    },
  }

  const wrapped = wrapLangChainTool(guard, tool, { mode: 'check' })
  assert.strictEqual(wrapped, tool)
  assert.equal(tool.description, 'test tool')
  assert.deepEqual(tool.metadata, { version: 1 })

  assert.equal(await tool.invoke({ expression: '2+2' }), 'invoke:2+2')
  assert.equal(await tool.call({ expression: '3+3' }), 'call:3+3')
  assert.equal(await tool._call({ expression: '4+4' }), '_call:4+4')

  assert.equal(invokeCalls, 1)
  assert.equal(callCalls, 1)
  assert.equal(privateCalls, 1)
  assert.equal(payloads.length, 3)
}

async function testOpenAIWrapperPayloadMapping() {
  const seenPayloads = []
  const guard = createMockGuard({
    decision: { outcome: 'allow', policyVersion: 'policy-openai' },
    onCheck(tool, payload) {
      seenPayloads.push({ tool, payload })
    },
  })

  const wrappedString = wrapOpenAITool(
    guard,
    async (input) => ({ ok: true, input }),
    { tool: 'bash', mode: 'check' }
  )

  const wrappedObject = wrapOpenAITool(
    guard,
    async (input) => ({ ok: true, input }),
    { tool: 'web_search', mode: 'check' }
  )

  const wrappedCustom = wrapOpenAITool(
    guard,
    async (input) => ({ ok: true, input }),
    {
      tool: 'web_search',
      mode: 'check',
      payloadMapper(input) {
        return JSON.stringify({ q: input.query, source: 'custom' })
      },
    }
  )

  await wrappedString('echo hello')
  await wrappedObject({ query: 'agent-guard' })
  await wrappedCustom({ query: 'priority' })

  assert.equal(seenPayloads[0].payload, JSON.stringify({ command: 'echo hello' }))
  assert.equal(seenPayloads[1].payload, JSON.stringify({ query: 'agent-guard' }))
  assert.equal(
    seenPayloads[2].payload,
    JSON.stringify({ q: 'priority', source: 'custom' })
  )
}

async function testAdapterExecutionErrorWrapping() {
  const guard = {
    check() {
      throw new Error('native check failed')
    },
    execute() {
      return Promise.resolve()
    },
  }

  const guarded = createGuardedExecutor(guard, {
    mode: 'check',
    tool: 'web_search',
  })(async () => 'unused')

  await expectRejects(
    () => guarded({ query: 'boom' }),
    AgentGuardExecutionError,
    (error) => {
      assert.equal(error.status, 'error')
    }
  )
}

async function main() {
  await testCreateGuardedExecutorCheckAllow()
  await testCreateGuardedExecutorCheckDeny()
  await testCreateGuardedExecutorCheckAsk()
  await testCreateGuardedExecutorEnforceExecutedAndMapped()
  await testCreateGuardedExecutorEnforceFailures()
  await testCreateGuardedExecutorAutoMode()
  await testCreateGuardedExecutorAutoFailsClosedOnInvalidPolicyVerification()
  await testLangChainWrapperCompatibility()
  await testOpenAIWrapperPayloadMapping()
  await testAdapterExecutionErrorWrapping()
  console.log('Node adapter tests passed.')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
