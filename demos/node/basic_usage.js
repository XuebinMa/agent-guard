const { Guard } = require('../../crates/agent-guard-node/index.js')

const yaml = `
version: 1
default_mode: workspace_write
rules:
  - tool: bash
    allow: ["ls"]
    deny: ["rm -rf /"]
`

async function runDemo() {
  try {
    const guard = Guard.fromYaml(yaml)
    console.log('=== agent-guard Node.js Demo ===')
    console.log('Policy version:', guard.policyVersion())

    // 1. Sync check
    console.log('\n[CHECK] tool: bash, command: ls -la')
    const d1 = guard.check('bash', JSON.stringify({ command: 'ls -la' }))
    console.log(`Outcome: ${d1.outcome.toUpperCase()}`)

    // 2. Async execute
    console.log('\n[EXECUTE] tool: bash, command: ls -la')
    const e1 = await guard.execute('bash', JSON.stringify({ command: 'ls -la' }))
    console.log(`Outcome: ${e1.outcome.toUpperCase()}`)
    if (e1.output) {
      console.log('Stdout:', e1.output.stdout.trim())
    }

    // 3. Denied execution
    console.log('\n[EXECUTE] tool: bash, command: rm -rf /')
    const e2 = await guard.execute('bash', JSON.stringify({ command: 'rm -rf /' }))
    console.log(`Outcome: ${e2.outcome.toUpperCase()}`)
    if (e2.decision) {
        console.log(`Reason: ${e2.decision.message}`)
    }

  } catch (e) {
    console.error('Demo failed:', e)
    process.exit(1)
  }
}

runDemo()
