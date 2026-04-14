'use strict'

const { tool } = require('@openai/agents')
const { z } = require('zod')
const { Guard, wrapOpenAITool } = require('..')

const policy = `
version: 1
default_mode: workspace_write
tools:
  custom:
    web_search: {}
`

async function main() {
  const guard = Guard.fromYaml(policy)

  const execute = wrapOpenAITool(
    guard,
    async (input) => ({
      ok: true,
      query: input.query,
      topResult: `stubbed result for ${input.query}`,
    }),
    {
      tool: 'web_search',
      mode: 'check',
      trustLevel: 'Trusted',
    }
  )

  const frameworkTool = tool({
    name: 'web_search',
    description: 'Search the web',
    parameters: z.object({
      query: z.string(),
    }),
    execute,
  })

  const result = await frameworkTool.invoke(
    undefined,
    JSON.stringify({ query: 'agent-guard adapters' }),
    undefined
  )
  console.log(result)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
