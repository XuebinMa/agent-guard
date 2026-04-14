'use strict'

const { Guard, wrapOpenAITool } = require('../index.js')

const policy = `
version: 1
default_mode: workspace_write
tools:
  custom:
    web_search: {}
`

async function main() {
  const guard = Guard.fromYaml(policy)

  const handler = wrapOpenAITool(
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

  const result = await handler({ query: 'agent-guard adapters' })
  console.log(result)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
