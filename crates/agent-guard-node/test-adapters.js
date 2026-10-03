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

function createMockGuard({
  decision,
  executeOutcome,
  runtimeOutcome,
  onCheck,
  onExecute,
  onRun,
  onReportHandoffResult,
}) {
  const guard = {
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

  if (
    runtimeOutcome !== undefined ||
    typeof onRun === 'function' ||
    typeof onReportHandoffResult === 'function'
  ) {
    guard.run = async function run(tool, payload, context) {
      if (typeof onRun === 'function') {
        onRun(tool, payload, context)
      }
      return runtimeOutcome
    }
    guard.reportHandoffResult = function reportHandoffResult(requestId, result) {
      if (typeof onReportHandoffResult === 'function') {
        return onReportHandoffResult(requestId, result)
      }
    }
  }

  return guard
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

async function testOmittedTrustDefaultsToUntrusted() {
  const seenTrustLevels = []
  let handlerCalls = 0
  const guard = {
    check(_tool, _payload, context) {
      seenTrustLevels.push(context.trustLevel)
      if (context.trustLevel === 'Trusted') {
        return { outcome: 'allow', policyVersion: 'policy-trust-default' }
      }
      return {
        outcome: 'deny',
        message: 'read-only policy blocks this mutation',
        code: 'WriteInReadOnlyMode',
        policyVersion: 'policy-trust-default',
      }
    },
    async execute() {
      throw new Error('execute must not be called in check mode')
    },
  }

  const omittedTrust = createGuardedExecutor(guard, {
    mode: 'check',
    tool: 'write_file',
  })(async () => {
    handlerCalls += 1
    return 'should-not-run'
  })

  await expectRejects(
    () => omittedTrust({ path: '/tmp/blocked', content: 'blocked' }),
    AgentGuardDeniedError,
    (error) => {
      assert.equal(error.code, 'WriteInReadOnlyMode')
    }
  )
  assert.equal(handlerCalls, 0)
  assert.deepEqual(seenTrustLevels, ['Untrusted'])

  const explicitTrust = createGuardedExecutor(guard, {
    mode: 'check',
    tool: 'write_file',
    trustLevel: 'Trusted',
  })(async () => {
    handlerCalls += 1
    return 'explicitly-trusted'
  })

  assert.equal(
    await explicitTrust({ path: '/tmp/allowed', content: 'allowed' }),
    'explicitly-trusted'
  )
  assert.equal(handlerCalls, 1)
  assert.deepEqual(seenTrustLevels, ['Untrusted', 'Trusted'])
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

async function testCreateGuardedExecutorAutoFallsBackToCheckWithoutRuntimeApi() {
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

async function testCreateGuardedExecutorAutoShellUsesExecute() {
  let checkCalls = 0
  let runCalls = 0
  let handlerCalls = 0
  const rawOutcome = {
    status: 'executed',
    output: { exitCode: 0, stdout: 'auto-shell\n', stderr: '' },
    policyVersion: 'policy-auto-shell',
    sandboxType: 'none',
  }
  const guard = createMockGuard({
    decision: { outcome: 'allow' },
    executeOutcome: rawOutcome,
    runtimeOutcome: { status: 'handoff', requestId: 'must-not-run' },
    onCheck() {
      checkCalls += 1
    },
    onRun() {
      runCalls += 1
    },
  })

  const guarded = createGuardedExecutor(guard, {
    mode: 'auto',
    tool: 'bash',
    resultMapper(outcome) {
      return outcome.output.stdout.trim()
    },
  })(async () => {
    handlerCalls += 1
    return 'should-not-run'
  })

  assert.equal(await guarded('echo auto-shell'), 'auto-shell')
  assert.equal(checkCalls, 0)
  assert.equal(runCalls, 0)
  assert.equal(handlerCalls, 0)
}

async function testCreateGuardedExecutorAutoRequiresExactBashToolId() {
  let runCalls = 0
  let executeCalls = 0
  const guard = createMockGuard({
    executeOutcome: {
      status: 'executed',
      output: { exitCode: 0, stdout: 'must-not-execute', stderr: '' },
    },
    runtimeOutcome: {
      status: 'handoff',
      requestId: 'request-custom-shell-alias',
      policyVersion: 'policy-custom-shell-alias',
    },
    onExecute() {
      executeCalls += 1
    },
    onRun(tool, payload) {
      runCalls += 1
    },
  })

  for (const tool of [
    'shell',
    'terminal',
    'BASH',
    'sh',
    'zsh',
    'cmd',
    'powershell',
    'pwsh',
  ]) {
    assert.throws(
      () => createGuardedExecutor(guard, { mode: 'auto', tool }),
      (error) => {
        assert.ok(error instanceof AgentGuardExecutionError)
        assert.equal(error.code, 'UnsupportedShellAlias')
        assert.match(error.message, /exact ID "bash"/)
        return true
      }
    )
  }

  assert.equal(executeCalls, 0)
  assert.equal(runCalls, 0)
}

async function testCreateGuardedExecutorAutoHandoffReportsSuccessOnce() {
  const runCalls = []
  const reports = []
  let handlerCalls = 0
  const guard = createMockGuard({
    runtimeOutcome: {
      status: 'handoff',
      requestId: 'request-success',
      policyVersion: 'policy-auto-handoff',
    },
    onCheck() {
      throw new Error('check must not be called when the runtime API is available')
    },
    onRun(tool, payload, context) {
      runCalls.push({ tool, payload, context })
    },
    onReportHandoffResult(requestId, result) {
      reports.push({ requestId, result })
    },
  })

  const guarded = createGuardedExecutor(guard, {
    mode: 'auto',
    tool: 'web_search',
    trustLevel: 'Trusted',
  })(async (input) => {
    handlerCalls += 1
    return { ok: true, input }
  })

  const input = { query: 'agent guard' }
  assert.deepEqual(await guarded(input), { ok: true, input })
  assert.equal(handlerCalls, 1)
  assert.deepEqual(runCalls, [
    {
      tool: 'web_search',
      payload: JSON.stringify(input),
      context: { trustLevel: 'Trusted' },
    },
  ])
  assert.equal(reports.length, 1)
  assert.equal(reports[0].requestId, 'request-success')
  assert.equal(reports[0].result.exitCode, 0)
  assert.ok(reports[0].result.durationMs >= 0)
  assert.equal(reports[0].result.stderr, undefined)
}

async function testCreateGuardedExecutorAutoHandoffPreservesHandlerError() {
  const reports = []
  const handlerError = new Error('host handler failed')
  const reportError = new Error('handoff report failed')
  const guard = createMockGuard({
    runtimeOutcome: {
      status: 'handoff',
      requestId: 'request-failure',
      policyVersion: 'policy-auto-handoff',
    },
    onReportHandoffResult(requestId, result) {
      reports.push({ requestId, result })
      throw reportError
    },
  })

  const guarded = createGuardedExecutor(guard, {
    mode: 'auto',
    tool: 'web_search',
  })(async () => {
    throw handlerError
  })

  let caught
  try {
    await guarded({ query: 'explode' })
  } catch (error) {
    caught = error
  }

  assert.strictEqual(caught, handlerError)
  assert.strictEqual(caught.agentGuardReportError, reportError)
  assert.equal(reports.length, 1)
  assert.equal(reports[0].requestId, 'request-failure')
  assert.equal(reports[0].result.exitCode, 1)
  assert.ok(reports[0].result.durationMs >= 0)
  assert.equal(reports[0].result.stderr, 'host handler failed')
}

async function testCreateGuardedExecutorAutoHandoffRejectsApparentSuccessWithReportError() {
  let reportCalls = 0
  const reportError = new Error('unknown or already reported request ID')
  const guard = createMockGuard({
    runtimeOutcome: {
      status: 'handoff',
      requestId: 'request-stale',
      policyVersion: 'policy-auto-handoff',
      policyVerificationStatus: 'unsigned',
    },
    onReportHandoffResult() {
      reportCalls += 1
      throw reportError
    },
  })

  const guarded = createGuardedExecutor(guard, {
    mode: 'auto',
    tool: 'web_search',
  })(async () => 'host-result')

  await expectRejects(
    () => guarded({ query: 'stale' }),
    AgentGuardExecutionError,
    (error) => {
      assert.strictEqual(error.cause, reportError)
      assert.match(error.message, /host action already completed but agent-guard could not record/)
      assert.equal(error.hostActionCompleted, true)
      assert.equal(error.hostResult, 'host-result')
      assert.equal(error.code, 'HandoffReportFailedAfterExecution')
      assert.equal(error.policyVersion, 'policy-auto-handoff')
      assert.equal(error.policyVerificationStatus, 'unsigned')
      assert.equal(error.policyVerificationError, undefined)
      assert.equal(error.requestId, 'request-stale')
      assert.equal(error.handoffReport.exitCode, 0)
      assert.ok(error.handoffReport.durationMs >= 0)
    }
  )
  assert.equal(reportCalls, 1)
}

async function testCreateGuardedExecutorAutoRuntimeBlocksWithoutHandlerOrReport() {
  for (const runtimeOutcome of [
    {
      status: 'denied',
      decision: {
        outcome: 'deny',
        message: 'blocked by runtime policy',
        code: 'DeniedByRule',
        matchedRule: 'web_search.deny[0]',
      },
      policyVersion: 'policy-runtime-deny',
    },
    {
      status: 'ask_for_approval',
      decision: {
        outcome: 'ask_for_approval',
        message: 'approval required',
        askPrompt: 'Approve web search?',
        code: 'AskRequired',
      },
      policyVersion: 'policy-runtime-ask',
    },
  ]) {
    let handlerCalls = 0
    let reportCalls = 0
    const guard = createMockGuard({
      runtimeOutcome,
      onReportHandoffResult() {
        reportCalls += 1
      },
    })
    const guarded = createGuardedExecutor(guard, {
      mode: 'auto',
      tool: 'web_search',
    })(async () => {
      handlerCalls += 1
      return 'should-not-run'
    })

    const ExpectedError =
      runtimeOutcome.status === 'denied'
        ? AgentGuardDeniedError
        : AgentGuardAskRequiredError
    await expectRejects(
      () => guarded({ query: 'blocked' }),
      ExpectedError,
      (error) => {
        assert.equal(error.policyVersion, runtimeOutcome.policyVersion)
        assert.equal(error.code, runtimeOutcome.decision.code)
      }
    )
    assert.equal(handlerCalls, 0)
    assert.equal(reportCalls, 0)
  }
}

async function testCreateGuardedExecutorAutoRejectsInvalidRuntimeHandoff() {
  let handlerCalls = 0
  let reportCalls = 0
  const guard = createMockGuard({
    runtimeOutcome: {
      status: 'handoff',
      requestId: 'request-invalid-runtime',
      policyVersion: 'policy-invalid-runtime',
      policyVerificationStatus: 'invalid',
      policyVerificationError: 'signature verification failed',
    },
    onReportHandoffResult() {
      reportCalls += 1
    },
  })
  const guarded = createGuardedExecutor(guard, {
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
      assert.equal(error.code, 'PolicyVerificationFailed')
      assert.equal(error.policyVersion, 'policy-invalid-runtime')
      assert.equal(error.policyVerificationStatus, 'invalid')
    }
  )
  assert.equal(handlerCalls, 0)
  assert.equal(reportCalls, 0)
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

async function testCreateGuardedExecutorCheckFailsClosedOnInvalidPolicyVerification() {
  let handlerCalls = 0
  const invalidGuard = createMockGuard({
    decision: {
      outcome: 'allow',
      policyVersion: 'policy-check-invalid',
      policyVerificationStatus: 'invalid',
      policyVerificationError: 'signature verification failed',
    },
  })

  const guarded = createGuardedExecutor(invalidGuard, {
    mode: 'check',
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

async function testLangChainDelayedNestedEntryCannotReuseTransitionTicket() {
  let runs = 0
  let reports = 0
  const actions = []
  let resolveInner
  let rejectInner
  const innerFinished = new Promise((resolve, reject) => {
    resolveInner = resolve
    rejectInner = reject
  })
  const guard = {
    check() {
      throw new Error('auto with runtime API must not call check')
    },
    async execute() {
      throw new Error('custom auto tool must not call execute')
    },
    async run() {
      runs += 1
      return {
        status: 'handoff',
        requestId: `request-delayed-${runs}`,
        policyVersion: 'policy-delayed-transition',
      }
    },
    reportHandoffResult() {
      reports += 1
    },
  }
  const tool = {
    name: 'calculator',
    invoke(input) {
      actions.push(`invoke:${input}`)
      if (input === 'outer') {
        setTimeout(() => {
          Promise.resolve(this.call('inner')).then(resolveInner, rejectInner)
        }, 0)
      }
      return `invoke:${input}`
    },
    call(input) {
      actions.push(`call:${input}`)
      return `call:${input}`
    },
  }

  wrapLangChainTool(guard, tool, { mode: 'auto', tool: 'calculator' })

  assert.equal(await tool.invoke('outer'), 'invoke:outer')
  assert.equal(await innerFinished, 'call:inner')
  assert.equal(runs, 2, 'the delayed public entry needs a fresh Guard run')
  assert.equal(reports, 2, 'both completed host actions need terminal reports')
  assert.deepEqual(actions, ['invoke:outer', 'call:inner'])
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
  await testOmittedTrustDefaultsToUntrusted()
  await testCreateGuardedExecutorCheckDeny()
  await testCreateGuardedExecutorCheckAsk()
  await testCreateGuardedExecutorEnforceExecutedAndMapped()
  await testCreateGuardedExecutorEnforceFailures()
  await testCreateGuardedExecutorAutoFallsBackToCheckWithoutRuntimeApi()
  await testCreateGuardedExecutorAutoShellUsesExecute()
  await testCreateGuardedExecutorAutoRequiresExactBashToolId()
  await testCreateGuardedExecutorAutoHandoffReportsSuccessOnce()
  await testCreateGuardedExecutorAutoHandoffPreservesHandlerError()
  await testCreateGuardedExecutorAutoHandoffRejectsApparentSuccessWithReportError()
  await testCreateGuardedExecutorAutoRuntimeBlocksWithoutHandlerOrReport()
  await testCreateGuardedExecutorAutoRejectsInvalidRuntimeHandoff()
  await testCreateGuardedExecutorAutoFailsClosedOnInvalidPolicyVerification()
  await testCreateGuardedExecutorCheckFailsClosedOnInvalidPolicyVerification()
  await testLangChainWrapperCompatibility()
  await testLangChainDelayedNestedEntryCannotReuseTransitionTicket()
  await testOpenAIWrapperPayloadMapping()
  await testAdapterExecutionErrorWrapping()
  console.log('Node adapter tests passed.')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
