'use strict'

const {
  Guard,
  wrapOpenAITool,
  AgentGuardDeniedError,
  AgentGuardAskRequiredError,
} = require('..')

const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - prefix: "echo summary:"
    ask:
      - prefix: "git push"
  custom:
    web_search: {}
`)

const guardedSearch = wrapOpenAITool(
  guard,
  async (input) => {
    return {
      query: input.query,
      summary: `summary:${input.query}`,
    }
  },
  {
    tool: 'web_search',
    mode: 'check',
    trustLevel: 'Trusted',
  }
)

const guardedShell = wrapOpenAITool(
  guard,
  async () => {
    throw new Error('shell handler should not run in enforce mode')
  },
  {
    tool: 'bash',
    mode: 'enforce',
    trustLevel: 'Trusted',
    resultMapper: (outcome) => outcome.output?.stdout.trim() ?? '',
  }
)

async function main() {
  const search = await guardedSearch({ query: 'agent runtime receipts' })
  console.log('Step 1 search:', search)

  const safeCommand = `echo summary:${search.query}`
  const safeResult = await guardedShell({ command: safeCommand })
  console.log('Step 2 safe shell:', safeResult)

  try {
    await guardedShell({ command: 'git push origin main' })
  } catch (error) {
    if (
      error instanceof AgentGuardDeniedError ||
      error instanceof AgentGuardAskRequiredError
    ) {
      console.log('Step 3 blocked shell:', error.name, error.code)
      return
    }
    throw error
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
