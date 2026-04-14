'use strict'

const { Guard, wrapOpenAITool } = require('../index.js')

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

  const checkHandler = wrapOpenAITool(
    guard,
    async (input) => `ORIGINAL:${input}`,
    {
      tool: 'bash',
      mode: 'check',
    }
  )

  const enforceHandler = wrapOpenAITool(
    guard,
    async () => 'UNUSED',
    {
      tool: 'bash',
      mode: 'enforce',
      resultMapper: (outcome) => outcome.output?.stdout ?? '',
    }
  )

  console.log('check ->', await checkHandler('echo from-original'))
  console.log('enforce ->', (await enforceHandler('echo from-sandbox')).trim())
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
