'use strict'

const { AsyncLocalStorage } = require('async_hooks')

const DEFAULT_MODE = 'enforce'
const DEFAULT_SHELL_TOOL = 'bash'
const DEFAULT_TRUST_LEVEL = 'Untrusted'
const SHELL_PAYLOAD_TOOL_NAMES = new Set(['bash', 'shell', 'terminal'])
const OWNED_SHELL_TOOL_NAMES = new Set(['bash'])
const SHELL_LIKE_TOOL_NAMES = new Set([
  'bash',
  'bash.exe',
  'shell',
  'terminal',
  'sh',
  'sh.exe',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
])

class AgentGuardAdapterError extends Error {
  constructor(message, details = {}) {
    super(message)
    this.name = new.target.name
    this.decision = details.decision
    this.decisionDetail = details.decisionDetail
    this.policyVersion = details.policyVersion
    this.sandboxType = details.sandboxType
    this.receipt = details.receipt
    this.status = details.status
    this.code = details.code
    this.matchedRule = details.matchedRule
    this.askPrompt = details.askPrompt
    this.policyVerificationStatus = details.policyVerificationStatus
    this.policyVerificationError = details.policyVerificationError
    this.hostActionCompleted = details.hostActionCompleted || false
    this.hostResult = details.hostResult
    this.requestId = details.requestId
    this.handoffReport = details.handoffReport
    if (details.cause !== undefined) {
      this.cause = details.cause
    }
  }
}

class AgentGuardDeniedError extends AgentGuardAdapterError {}

class AgentGuardAskRequiredError extends AgentGuardAdapterError {}

class AgentGuardExecutionError extends AgentGuardAdapterError {}

function fallbackNormalizePayload(tool, rawInput) {
  const toolName = String(tool || '')
  if (SHELL_PAYLOAD_TOOL_NAMES.has(toolName)) {
    return JSON.stringify({ command: rawInput })
  }
  return JSON.stringify({ input: rawInput })
}

function isThenable(value) {
  return Boolean(value) && typeof value.then === 'function'
}

function isPlainObjectLike(value) {
  return value !== null && typeof value === 'object'
}

function validateMode(mode) {
  const resolvedMode = mode || DEFAULT_MODE
  if (resolvedMode !== 'check' && resolvedMode !== 'enforce' && resolvedMode !== 'auto') {
    throw new AgentGuardExecutionError(`Unsupported adapter mode "${resolvedMode}"`, {
      status: 'error',
    })
  }
  return resolvedMode
}

function isShellToolName(tool) {
  return OWNED_SHELL_TOOL_NAMES.has(String(tool || ''))
}

function hasRuntimeApi(guard) {
  return (
    typeof guard.run === 'function' &&
    typeof guard.reportHandoffResult === 'function'
  )
}

function resolveMode(mode, tool, guard) {
  if (mode !== 'auto') {
    return mode
  }
  if (isShellToolName(tool)) {
    return 'enforce'
  }
  const normalizedTool = String(tool || '').toLowerCase()
  if (SHELL_LIKE_TOOL_NAMES.has(normalizedTool)) {
    throw new AgentGuardExecutionError(
      `Auto mode refuses shell-like custom tool ID "${tool}"; map a real Bash-backed tool to the exact ID "bash" or choose an explicit mode`,
      {
        status: 'configuration_error',
        code: 'UnsupportedShellAlias',
      }
    )
  }
  return hasRuntimeApi(guard) ? 'run' : 'check'
}

function resolveTool(explicitTool, fallbackTool, requireExplicit) {
  if (typeof explicitTool === 'string' && explicitTool.trim() !== '') {
    return explicitTool
  }
  if (typeof fallbackTool === 'string' && fallbackTool.trim() !== '') {
    return fallbackTool
  }
  if (requireExplicit) {
    throw new AgentGuardExecutionError(
      'Adapter option "tool" is required for this wrapper',
      { status: 'error' }
    )
  }
  return DEFAULT_SHELL_TOOL
}

function resolveWorkingDirectory(workingDirectory) {
  if (typeof workingDirectory === 'function') {
    return workingDirectory()
  }
  return workingDirectory
}

function buildContext(options) {
  const context = {
    trustLevel: options.trustLevel || DEFAULT_TRUST_LEVEL,
  }

  if (options.agentId !== undefined) {
    context.agentId = options.agentId
  }
  if (options.sessionId !== undefined) {
    context.sessionId = options.sessionId
  }
  if (options.actor !== undefined) {
    context.actor = options.actor
  }

  const workingDirectory = resolveWorkingDirectory(options.workingDirectory)
  if (workingDirectory !== undefined) {
    context.workingDirectory = workingDirectory
  }

  return context
}

function serializePayload(normalizePayload, tool, input, payloadMapper) {
  if (typeof payloadMapper === 'function') {
    const mapped = payloadMapper(input)
    if (typeof mapped !== 'string') {
      throw new AgentGuardExecutionError('payloadMapper must return a JSON string payload', {
        status: 'error',
      })
    }
    return mapped
  }

  if (typeof input === 'string') {
    return normalizePayload(tool, input)
  }

  if (isPlainObjectLike(input)) {
    return JSON.stringify(input)
  }

  return JSON.stringify({ input })
}

function buildDecisionError(decision, extras = {}) {
  const outcome = decision && decision.outcome ? decision.outcome : 'deny'
  const isAsk =
    outcome === 'ask_user' ||
    outcome === 'ask_for_approval' ||
    outcome === 'ask_required'
  const status = isAsk ? 'ask_required' : 'denied'
  const message =
    decision && (decision.askPrompt || decision.message)
      ? decision.askPrompt || decision.message
      : isAsk
        ? 'agent-guard requires user approval before tool execution'
        : 'agent-guard denied tool execution'

  const details = {
    decision: outcome,
    decisionDetail: decision,
    policyVersion:
      extras.policyVersion ||
      (decision && (decision.policyVersion || decision.policy_version)) ||
      undefined,
    sandboxType: extras.sandboxType,
    receipt: extras.receipt,
    status,
    code: decision ? decision.code : undefined,
    matchedRule: decision
      ? decision.matchedRule || decision.matched_rule
      : undefined,
    askPrompt: decision ? decision.askPrompt || decision.ask_prompt : undefined,
    policyVerificationStatus:
      extras.policyVerificationStatus ||
      (decision &&
        (decision.policyVerificationStatus ||
          decision.policy_verification_status)) ||
      undefined,
    policyVerificationError:
      extras.policyVerificationError ||
      (decision &&
        (decision.policyVerificationError ||
          decision.policy_verification_error)) ||
      undefined,
    cause: extras.cause,
  }

  if (isAsk) {
    return new AgentGuardAskRequiredError(message, details)
  }
  return new AgentGuardDeniedError(message, details)
}

function runtimeStatus(outcome) {
  return outcome ? outcome.status || outcome.outcome : undefined
}

function buildRuntimeDecisionError(outcome) {
  const status = runtimeStatus(outcome)
  const decision = outcome && outcome.decision
    ? outcome.decision
    : {
        outcome: status,
        message: outcome ? outcome.message : undefined,
        code: outcome ? outcome.code : undefined,
        matchedRule: outcome ? outcome.matchedRule : undefined,
        askPrompt: outcome ? outcome.askPrompt : undefined,
      }

  return buildDecisionError(decision, {
    policyVersion: outcome
      ? outcome.policyVersion || outcome.policy_version
      : undefined,
    sandboxType: outcome
      ? outcome.sandboxType || outcome.sandbox_type
      : undefined,
    receipt: outcome ? outcome.receipt : undefined,
    policyVerificationStatus: outcome
      ? outcome.policyVerificationStatus ||
        outcome.policy_verification_status
      : undefined,
    policyVerificationError: outcome
      ? outcome.policyVerificationError || outcome.policy_verification_error
      : undefined,
  })
}

function elapsedMilliseconds(startedAt) {
  return Number((process.hrtime.bigint() - startedAt) / 1_000_000n)
}

function handoffErrorMessage(error) {
  if (error instanceof Error && error.message) {
    return error.message
  }
  return String(error)
}

function attachHandoffReportError(handlerError, reportError) {
  if (
    handlerError !== null &&
    (typeof handlerError === 'object' || typeof handlerError === 'function')
  ) {
    try {
      Object.defineProperty(handlerError, 'agentGuardReportError', {
        configurable: true,
        enumerable: false,
        value: reportError,
      })
      return
    } catch (_) {
      // Fall through to a process warning for frozen host errors.
    }
  }
  process.emitWarning(
    `agent-guard could not record the handoff result: ${handoffErrorMessage(reportError)}`,
    { code: 'AGENT_GUARD_HANDOFF_REPORT_FAILED' }
  )
}

async function dispatchViaRun({
  guard,
  tool,
  payload,
  context,
  handler,
  receiver,
  input,
  rest,
}) {
  let outcome
  try {
    outcome = await guard.run(tool, payload, context)
  } catch (error) {
    throw buildExecuteError(error)
  }

  enforceVerifiedPolicy(outcome)

  const status = runtimeStatus(outcome)
  if (status === 'handoff') {
    const requestId = outcome && (outcome.requestId || outcome.request_id)
    if (typeof requestId !== 'string' || requestId.length === 0) {
      throw new AgentGuardExecutionError(
        'agent-guard returned a handoff without a request ID',
        {
          decision: 'error',
          policyVersion: outcome
            ? outcome.policyVersion || outcome.policy_version
            : undefined,
          status: 'error',
        }
      )
    }

    const startedAt = process.hrtime.bigint()
    let result
    try {
      result = await handler.call(receiver, input, ...rest)
    } catch (handlerError) {
      const report = {
        exitCode: 1,
        durationMs: elapsedMilliseconds(startedAt),
        stderr: handoffErrorMessage(handlerError),
      }
      try {
        await guard.reportHandoffResult(requestId, report)
      } catch (reportError) {
        // Preserve the original host failure while attaching the audit
        // failure so callers cannot mistake the lifecycle for fully recorded.
        attachHandoffReportError(handlerError, reportError)
      }
      throw handlerError
    }

    const report = {
      exitCode: 0,
      durationMs: elapsedMilliseconds(startedAt),
    }
    try {
      await guard.reportHandoffResult(requestId, report)
    } catch (reportError) {
      throw new AgentGuardExecutionError(
        `host action already completed but agent-guard could not record its handoff result; do not retry automatically: ${handoffErrorMessage(reportError)}`,
        {
          decision: 'error',
          policyVersion: outcome
            ? outcome.policyVersion || outcome.policy_version
            : undefined,
          policyVerificationStatus: outcome
            ? outcome.policyVerificationStatus ||
              outcome.policy_verification_status
            : undefined,
          policyVerificationError: outcome
            ? outcome.policyVerificationError ||
              outcome.policy_verification_error
            : undefined,
          status: 'report_failed_after_execution',
          code: 'HandoffReportFailedAfterExecution',
          hostActionCompleted: true,
          hostResult: result,
          requestId,
          handoffReport: report,
          cause: reportError,
        }
      )
    }
    return result
  }

  if (status === 'executed' || status === 'execute') {
    return outcome
  }

  if (
    status === 'denied' ||
    status === 'deny' ||
    status === 'ask_for_approval' ||
    status === 'ask_user' ||
    status === 'ask_required'
  ) {
    throw buildRuntimeDecisionError(outcome)
  }

  throw new AgentGuardExecutionError(
    'agent-guard run returned an unknown outcome',
    {
      decision: 'error',
      policyVersion: outcome
        ? outcome.policyVersion || outcome.policy_version
        : undefined,
      status: status || 'error',
    }
  )
}

function buildExecuteError(error, policyVersion) {
  if (error instanceof AgentGuardAdapterError) {
    return error
  }
  const message =
    error instanceof Error && error.message
      ? error.message
      : 'agent-guard adapter execution failed'
  return new AgentGuardExecutionError(message, {
    decision: 'error',
    policyVersion,
    status: 'error',
    cause: error,
  })
}

function enforceVerifiedPolicy(decision) {
  const verificationStatus = decision
    ? decision.policyVerificationStatus ||
      decision.policy_verification_status
    : undefined
  if (!decision || verificationStatus !== 'invalid') {
    return
  }

  const verificationDecision = {
    outcome: 'deny',
    message:
      decision.policyVerificationError ||
      decision.policy_verification_error ||
      'agent-guard refuses to continue with an invalid policy signature',
    code: 'PolicyVerificationFailed',
    policyVersion: decision.policyVersion || decision.policy_version,
    policyVerificationStatus: verificationStatus,
    policyVerificationError:
      decision.policyVerificationError ||
      decision.policy_verification_error,
  }

  throw buildDecisionError(verificationDecision)
}

function handleExecuteOutcome(outcome, originalInput, resultMapper) {
  const status = outcome ? outcome.status || outcome.outcome : undefined

  if (status === 'executed') {
    return typeof resultMapper === 'function'
      ? resultMapper(outcome, originalInput)
      : outcome
  }

  if (status === 'denied') {
    throw buildDecisionError(outcome.decision, {
      policyVersion: outcome.policyVersion || outcome.policy_version,
      sandboxType: outcome.sandboxType || outcome.sandbox_type,
      receipt: outcome.receipt,
    })
  }

  if (status === 'ask_required') {
    throw buildDecisionError(outcome.decision, {
      policyVersion: outcome.policyVersion || outcome.policy_version,
      sandboxType: outcome.sandboxType || outcome.sandbox_type,
      receipt: outcome.receipt,
    })
  }

  throw new AgentGuardExecutionError('agent-guard returned an unknown execution status', {
    decision: 'error',
    policyVersion: outcome ? outcome.policyVersion || outcome.policy_version : undefined,
    sandboxType: outcome ? outcome.sandboxType || outcome.sandbox_type : undefined,
    receipt: outcome ? outcome.receipt : undefined,
    status: status || 'error',
  })
}

function createAdapterExports(nativeApi = {}) {
  const normalizePayload = nativeApi.normalizePayload || fallbackNormalizePayload

  function createGuardedExecutor(guard, options = {}) {
    if (!guard || typeof guard.check !== 'function' || typeof guard.execute !== 'function') {
      throw new TypeError('createGuardedExecutor requires a guard with check() and execute()')
    }

    const requestedMode = validateMode(options.mode)
    const tool = resolveTool(options.tool, null, false)
    const mode = resolveMode(requestedMode, tool, guard)

    return function wrapHandler(handler) {
      if (typeof handler !== 'function') {
        throw new TypeError('createGuardedExecutor(...) expects a handler function to wrap')
      }

      return function guardedHandler(input, ...rest) {
        let payload
        let context

        try {
          payload = serializePayload(normalizePayload, tool, input, options.payloadMapper)
          context = buildContext(options)
        } catch (error) {
          throw buildExecuteError(error)
        }

        if (mode === 'enforce') {
          return Promise.resolve(guard.execute(tool, payload, context))
            .then((outcome) => handleExecuteOutcome(outcome, input, options.resultMapper))
            .catch((error) => {
              throw buildExecuteError(error)
            })
        }

        if (mode === 'run') {
          return dispatchViaRun({
            guard,
            tool,
            payload,
            context,
            handler,
            receiver: this,
            input,
            rest,
          })
        }

        let decision
        try {
          decision = guard.check(tool, payload, context)
        } catch (error) {
          throw buildExecuteError(error)
        }

        if (!decision || decision.outcome !== 'allow') {
          throw buildDecisionError(decision)
        }

        enforceVerifiedPolicy(decision)

        try {
          const result = handler.call(this, input, ...rest)
          return isThenable(result)
            ? result.catch((error) => {
                throw error
              })
            : result
        } catch (error) {
          throw error
        }
      }
    }
  }

  function wrapOpenAITool(guard, handler, options = {}) {
    const tool = resolveTool(options.tool, null, true)
    return createGuardedExecutor(guard, { ...options, tool })(handler)
  }

  function wrapLangChainTool(guard, tool, options = {}) {
    if (!tool || typeof tool !== 'object') {
      throw new TypeError('wrapLangChainTool requires a tool object')
    }

    const toolName = resolveTool(options.tool, tool.name, false)
    const methodNames = ['invoke', 'call', '_call'].filter(
      (methodName) => typeof tool[methodName] === 'function'
    )

    if (methodNames.length === 0) {
      throw new TypeError(
        'Provided object does not look like a LangChain tool (missing invoke/call/_call)'
      )
    }

    // A real LangChain DynamicTool.invoke() calls call(), which then calls
    // _call(). Because all three are public entry points we wrap each one, but
    // one logical invocation must produce exactly one Guard lifecycle. A
    // single-use transition ticket suppresses only the expected next framework
    // method. The leaf method runs without a ticket, so work scheduled by the
    // actual tool implementation cannot inherit a blanket Guard bypass.
    const invocationContext = new AsyncLocalStorage()
    const availableMethods = new Set(methodNames)
    const nextMethod = new Map([
      [
        'invoke',
        availableMethods.has('call')
          ? 'call'
          : availableMethods.has('_call')
            ? '_call'
            : null,
      ],
      ['call', availableMethods.has('_call') ? '_call' : null],
      ['_call', null],
    ])

    function invokeOriginal(methodName, originalMethod, receiver, args) {
      const expected = nextMethod.get(methodName)
      const ticket = expected
        ? { expected, consumed: false, closed: false }
        : null
      return invocationContext.run(ticket, () => {
        let result
        try {
          result = originalMethod.apply(receiver, args)
        } catch (error) {
          if (ticket) {
            ticket.closed = true
          }
          throw error
        }
        if (ticket && isThenable(result)) {
          return Promise.resolve(result).finally(() => {
            ticket.closed = true
          })
        }
        if (ticket) {
          ticket.closed = true
        }
        return result
      })
    }

    for (const methodName of methodNames) {
      const originalMethod = tool[methodName]
      const wrapHandler = createGuardedExecutor(guard, { ...options, tool: toolName })
      const guardedMethod = wrapHandler(function invokeGuardedOriginal(value, ...handlerRest) {
        return invokeOriginal(
          methodName,
          originalMethod,
          this,
          [value, ...handlerRest]
        )
      })
      tool[methodName] = function guardedLangChainMethod(input, ...rest) {
        const ticket = invocationContext.getStore()
        if (
          ticket &&
          !ticket.consumed &&
          !ticket.closed &&
          ticket.expected === methodName
        ) {
          ticket.consumed = true
          return invokeOriginal(methodName, originalMethod, this, [input, ...rest])
        }
        return guardedMethod.call(this, input, ...rest)
      }
    }

    return tool
  }

  return {
    AgentGuardAdapterError,
    AgentGuardDeniedError,
    AgentGuardAskRequiredError,
    AgentGuardExecutionError,
    createGuardedExecutor,
    wrapLangChainTool,
    wrapOpenAITool,
  }
}

module.exports = {
  AgentGuardAdapterError,
  AgentGuardDeniedError,
  AgentGuardAskRequiredError,
  AgentGuardExecutionError,
  fallbackNormalizePayload,
  createAdapterExports,
}
