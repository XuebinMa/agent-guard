'use strict'

const { readFileSync } = require('fs')
const { join } = require('path')
const {
  Guard,
  wrapOpenAITool,
  AgentGuardDeniedError,
  AgentGuardAskRequiredError,
} = require('../..')

const policyPath = join(__dirname, 'policy.yaml')
const policyYaml = readFileSync(policyPath, 'utf8')

const guard = Guard.fromYaml(policyYaml)

const guardedShell = wrapOpenAITool(
  guard,
  async (input) => {
    return `ORIGINAL_HANDLER:${input.command}`
  },
  {
    tool: 'bash',
    mode: 'enforce',
    trustLevel: 'Trusted',
    agentId: 'quickstart-agent',
    actor: 'new-user',
    resultMapper: (outcome) => outcome.output?.stdout.trim() ?? '',
  }
)

async function runScenario(label, command) {
  console.log(`\n[${label}] ${command}`)

  try {
    const result = await guardedShell({ command })
    console.log('status: allowed')
    console.log('result:', result)
  } catch (error) {
    if (
      error instanceof AgentGuardDeniedError ||
      error instanceof AgentGuardAskRequiredError
    ) {
      console.log('status: blocked')
      console.log('error:', error.name)
      console.log('decision:', error.decision)
      console.log('code:', error.code)
      if (error.askPrompt) {
        console.log('askPrompt:', error.askPrompt)
      }
      return
    }

    throw error
  }
}

async function main() {
  console.log('Loaded policy from:', policyPath)
  console.log('Policy version:', guard.policyVersion())

  await runScenario('Allowed Example', 'echo hello from agent-guard')
  await runScenario('Blocked Example', 'git push origin main')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
