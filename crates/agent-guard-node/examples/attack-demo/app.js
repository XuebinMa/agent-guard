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

async function unsafeShell(input) {
  return `UNSAFE_HANDLER_WOULD_RUN:${input.command}`
}

const guardedShell = wrapOpenAITool(
  guard,
  async (input) => {
    return `ORIGINAL_HANDLER:${input.command}`
  },
  {
    tool: 'bash',
    mode: 'enforce',
    trustLevel: 'Trusted',
    agentId: 'attack-demo-agent',
    actor: 'demo-user',
    resultMapper: (outcome) => outcome.output?.stdout.trim() ?? '',
  }
)

async function compareScenario(label, command) {
  console.log(`\n=== ${label} ===`)
  console.log(`command: ${command}`)

  const unsafeResult = await unsafeShell({ command })
  console.log('without guard:', unsafeResult)

  try {
    const guardedResult = await guardedShell({ command })
    console.log('with guard: allowed')
    console.log('guard result:', guardedResult)
  } catch (error) {
    if (
      error instanceof AgentGuardDeniedError ||
      error instanceof AgentGuardAskRequiredError
    ) {
      console.log('with guard: blocked')
      console.log('guard error:', error.name)
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
  console.log('Attack demo policy:', policyPath)
  console.log('Policy version:', guard.policyVersion())

  await compareScenario('Safe Command', 'echo hello from attack demo')
  await compareScenario('Approval Required Command', 'git push origin main')
  await compareScenario('Destructive Command', 'rm -rf /')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
