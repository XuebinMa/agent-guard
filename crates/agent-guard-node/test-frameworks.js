'use strict'

const assert = require('assert/strict')
const { DynamicTool } = require('@langchain/core/tools')
const { tool: openAITool } = require('@openai/agents')
const { z } = require('zod')

const {
  Guard,
  wrapLangChainTool,
  wrapOpenAITool,
} = require('.')

async function testLangChainDynamicToolCheckMode() {
  const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  custom:
    calculator: {}
`)

  const callLog = []
  const calculator = new DynamicTool({
    name: 'calculator',
    description: 'Evaluate toy expressions',
    func: async (input) => {
      callLog.push(input)
      return `CALC:${input}`
    },
  })

  const wrapped = wrapLangChainTool(guard, calculator, {
    mode: 'check',
    tool: 'calculator',
  })

  assert.strictEqual(wrapped, calculator)
  assert.equal(wrapped.name, 'calculator')
  assert.equal(wrapped.description, 'Evaluate toy expressions')

  assert.equal(await wrapped.invoke('2+2'), 'CALC:2+2')
  assert.equal(await wrapped.call('3+3'), 'CALC:3+3')
  assert.equal(await wrapped._call('4+4'), 'CALC:4+4')
  assert.deepEqual(callLog, ['2+2', '3+3', '4+4'])
}

async function testLangChainDynamicToolEnforceMode() {
  const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - "echo"
`)

  let originalCalls = 0
  const shellTool = new DynamicTool({
    name: 'bash',
    description: 'Shell execution',
    func: async (input) => {
      originalCalls += 1
      return `ORIGINAL:${input}`
    },
  })

  wrapLangChainTool(guard, shellTool, {
    mode: 'enforce',
    resultMapper: (outcome) => outcome.output.stdout.trim(),
  })

  const result = await shellTool.invoke('echo langchain')
  assert.equal(result, 'langchain')
  assert.equal(originalCalls, 0)
}

async function testLangChainDynamicToolAutoHasOneLifecyclePerInvocation() {
  let runs = 0
  let reports = 0
  const callLog = []
  const guard = {
    check() {
      throw new Error('auto with a runtime API must not call check')
    },
    async execute() {
      throw new Error('a non-bash auto tool must not call execute')
    },
    async run() {
      runs += 1
      return {
        status: 'handoff',
        requestId: `request-${runs}`,
        policyVersion: 'framework-auto-policy',
      }
    },
    reportHandoffResult() {
      reports += 1
    },
  }
  const calculator = new DynamicTool({
    name: 'calculator',
    description: 'Evaluate concurrent toy expressions',
    func: async (input) => {
      callLog.push(input)
      await Promise.resolve()
      return `CALC:${input}`
    },
  })

  wrapLangChainTool(guard, calculator, {
    mode: 'auto',
    tool: 'calculator',
  })

  assert.deepEqual(
    await Promise.all([calculator.invoke('2+2'), calculator.invoke('3+3')]),
    ['CALC:2+2', 'CALC:3+3']
  )
  assert.equal(runs, 2, 'one run lifecycle per top-level invocation')
  assert.equal(reports, 2, 'one terminal report per top-level invocation')
  assert.deepEqual(callLog, ['2+2', '3+3'])
}

async function testLangChainDynamicToolReentrantInvocationStartsNewLifecycle() {
  let runs = 0
  let reports = 0
  const callLog = []
  const guard = {
    check() {
      throw new Error('auto with a runtime API must not call check')
    },
    async execute() {
      throw new Error('a non-bash auto tool must not call execute')
    },
    async run() {
      runs += 1
      return {
        status: 'handoff',
        requestId: `request-reentrant-${runs}`,
        policyVersion: 'framework-reentrant-policy',
      }
    },
    reportHandoffResult() {
      reports += 1
    },
  }

  let calculator
  calculator = new DynamicTool({
    name: 'calculator',
    description: 'Invoke the same tool from its host implementation',
    func: async (input) => {
      callLog.push(input)
      if (input === 'outer') {
        const inner = await calculator.invoke('inner')
        return `OUTER:${inner}`
      }
      return `CALC:${input}`
    },
  })

  wrapLangChainTool(guard, calculator, {
    mode: 'auto',
    tool: 'calculator',
  })

  assert.equal(await calculator.invoke('outer'), 'OUTER:CALC:inner')
  assert.equal(runs, 2, 'the reentrant host action needs its own Guard run')
  assert.equal(reports, 2, 'both host actions need terminal reports')
  assert.deepEqual(callLog, ['outer', 'inner'])
}

async function testOpenAIAgentsCheckMode() {
  const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  custom:
    web_search: {}
`)

  let originalCalls = 0
  const execute = wrapOpenAITool(
    guard,
    async (input) => {
      originalCalls += 1
      return { ok: true, query: input.query }
    },
    {
      tool: 'web_search',
      mode: 'check',
      trustLevel: 'Trusted',
    }
  )

  const frameworkTool = openAITool({
    name: 'web_search',
    description: 'Search the web',
    parameters: z.object({
      query: z.string(),
    }),
    execute,
  })

  const result = await frameworkTool.invoke(
    undefined,
    JSON.stringify({ query: 'agent-guard' }),
    undefined
  )

  assert.deepEqual(result, { ok: true, query: 'agent-guard' })
  assert.equal(originalCalls, 1)
}

async function testOpenAIAgentsEnforceMode() {
  const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - "echo"
`)

  let originalCalls = 0
  const execute = wrapOpenAITool(
    guard,
    async (input) => {
      originalCalls += 1
      return { bypassed: input.command }
    },
    {
      tool: 'bash',
      mode: 'enforce',
      resultMapper: (outcome) => outcome.output.stdout.trim(),
    }
  )

  const frameworkTool = openAITool({
    name: 'bash',
    description: 'Run shell commands',
    parameters: z.object({
      command: z.string(),
    }),
    execute,
  })

  const result = await frameworkTool.invoke(
    undefined,
    JSON.stringify({ command: 'echo openai' }),
    undefined
  )

  assert.equal(result, 'openai')
  assert.equal(originalCalls, 0)
}

async function testOpenAIAgentsBlockedMode() {
  const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    ask:
      - prefix: "git push"
`)

  let originalCalls = 0
  const execute = wrapOpenAITool(
    guard,
    async (input) => {
      originalCalls += 1
      return { bypassed: input.command }
    },
    {
      tool: 'bash',
      mode: 'check',
    }
  )

  const frameworkTool = openAITool({
    name: 'bash',
    description: 'Run shell commands',
    parameters: z.object({
      command: z.string(),
    }),
    execute,
  })

  const result = await frameworkTool.invoke(
    undefined,
    JSON.stringify({ command: 'git push origin main' }),
    undefined
  )

  assert.equal(typeof result, 'string')
  assert.match(result, /AgentGuardAskRequiredError|AgentGuardDeniedError/)
  assert.equal(originalCalls, 0)
}

async function main() {
  await testLangChainToolCallArgumentsHaveTheSamePolicyAsBareInput()
  await testLangChainDynamicToolCheckMode()
  await testLangChainDynamicToolEnforceMode()
  await testLangChainDynamicToolAutoHasOneLifecyclePerInvocation()
  await testLangChainDynamicToolReentrantInvocationStartsNewLifecycle()
  await testOpenAIAgentsCheckMode()
  await testOpenAIAgentsEnforceMode()
  await testOpenAIAgentsBlockedMode()
  console.log('Node framework compatibility tests passed.')
}

async function testLangChainToolCallArgumentsHaveTheSamePolicyAsBareInput() {
  for (const mode of ['check', 'auto']) {
    const guard = Guard.fromYaml(`
version: 1
default_mode: full_access
tools:
  custom:
    calculator:
      deny:
        - regex: '^\\{"input":"blocked-fixture"\\}$'
anomaly:
  enabled: false
audit:
  enabled: false
`)
    const calls = []
    const calculator = new DynamicTool({
      name: 'calculator', description: 'Local input normalization fixture',
      func: async input => { calls.push(input); return input },
    })
    wrapLangChainTool(guard, calculator, { mode })
    await assert.rejects(async () => calculator.invoke('blocked-fixture'), /denied|Denied/i)
    await assert.rejects(async () => calculator.invoke({
      type: 'tool_call', name: 'calculator', id: 'local-denied',
      args: { input: 'blocked-fixture' },
    }), /denied|Denied/i)
    assert.deepEqual(calls, [])
    const result = await calculator.invoke({
      type: 'tool_call', name: 'calculator', id: 'local-allowed',
      args: { input: 'allowed-fixture' },
    })
    assert.equal(result.content, 'allowed-fixture')
    assert.deepEqual(calls, ['allowed-fixture'])
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
