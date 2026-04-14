'use strict'

const { tool } = require('@openai/agents')
const { z } = require('zod')
const { Guard, wrapOpenAITool } = require('..')

const policy = `
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - "echo"
`

async function main() {
  const guard = Guard.fromYaml(policy)

  const checkExecute = wrapOpenAITool(
    guard,
    async (input) => `ORIGINAL:${input.command}`,
    {
      tool: 'bash',
      mode: 'check',
    }
  )

  const enforceExecute = wrapOpenAITool(
    guard,
    async () => 'UNUSED',
    {
      tool: 'bash',
      mode: 'enforce',
      resultMapper: (outcome) => outcome.output?.stdout ?? '',
    }
  )

  const checkTool = tool({
    name: 'bash',
    description: 'Shell tool with check mode',
    parameters: z.object({
      command: z.string(),
    }),
    execute: checkExecute,
  })

  const enforceTool = tool({
    name: 'bash',
    description: 'Shell tool with enforce mode',
    parameters: z.object({
      command: z.string(),
    }),
    execute: enforceExecute,
  })

  console.log(
    'check ->',
    await checkTool.invoke(undefined, JSON.stringify({ command: 'echo from-original' }), undefined)
  )
  console.log(
    'enforce ->',
    (
      await enforceTool.invoke(
        undefined,
        JSON.stringify({ command: 'echo from-sandbox' }),
        undefined
      )
    ).trim()
  )
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
