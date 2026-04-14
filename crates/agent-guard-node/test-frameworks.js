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
  await testLangChainDynamicToolCheckMode()
  await testLangChainDynamicToolEnforceMode()
  await testOpenAIAgentsCheckMode()
  await testOpenAIAgentsEnforceMode()
  await testOpenAIAgentsBlockedMode()
  console.log('Node framework compatibility tests passed.')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
