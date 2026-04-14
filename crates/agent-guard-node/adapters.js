'use strict'

const DEFAULT_MODE = 'enforce'
const DEFAULT_SHELL_TOOL = 'bash'
const DEFAULT_TRUST_LEVEL = 'Trusted'
const SHELL_TOOL_NAMES = new Set(['bash', 'shell', 'terminal', 'sh', 'zsh', 'cmd', 'powershell', 'pwsh'])

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
    if (details.cause !== undefined) {
      this.cause = details.cause
    }
  }
}

class AgentGuardDeniedError extends AgentGuardAdapterError {}

class AgentGuardAskRequiredError extends AgentGuardAdapterError {}

class AgentGuardExecutionError extends AgentGuardAdapterError {}

function fallbackNormalizePayload(tool, rawInput) {
  const normalizedTool = String(tool || '').toLowerCase()
  if (SHELL_TOOL_NAMES.has(normalizedTool)) {
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
  const status = outcome === 'ask_user' ? 'ask_required' : 'denied'
  const message =
    decision && (decision.askPrompt || decision.message)
      ? decision.askPrompt || decision.message
      : status === 'ask_required'
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
    matchedRule: decision ? decision.matchedRule : undefined,
    askPrompt: decision ? decision.askPrompt : undefined,
    cause: extras.cause,
  }

  if (outcome === 'ask_user') {
    return new AgentGuardAskRequiredError(message, details)
  }
  return new AgentGuardDeniedError(message, details)
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

    const mode = validateMode(options.mode)
    const tool = resolveTool(options.tool, null, false)

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

        let decision
        try {
          decision = guard.check(tool, payload, context)
        } catch (error) {
          throw buildExecuteError(error)
        }

        if (!decision || decision.outcome !== 'allow') {
          throw buildDecisionError(decision)
        }

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

    for (const methodName of methodNames) {
      const originalMethod = tool[methodName]
      const wrapHandler = createGuardedExecutor(guard, { ...options, tool: toolName })
      tool[methodName] = function guardedLangChainMethod(input, ...rest) {
        const guardedHandler = wrapHandler((value, ...handlerRest) =>
          originalMethod.call(this, value, ...handlerRest)
        )
        return guardedHandler.call(this, input, ...rest)
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
