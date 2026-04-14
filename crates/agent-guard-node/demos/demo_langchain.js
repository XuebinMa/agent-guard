'use strict'

const { Guard, wrapLangChainTool } = require('../index.js')

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

  const shellTool = {
    name: 'bash',
    description: 'Simple shell-like demo tool',
    async invoke(input) {
      return `ORIGINAL:${input}`
    },
  }

  wrapLangChainTool(guard, shellTool, {
    mode: 'enforce',
    resultMapper: (outcome) => outcome.output?.stdout ?? '',
  })

  const result = await shellTool.invoke('echo demo_langchain')
  console.log(result.trim())
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
