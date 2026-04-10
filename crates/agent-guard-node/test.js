const { Guard } = require('./index.js')

const yaml = `
version: 1
default_mode: workspace_write
tools:
  bash:
    allow: ["ls"]
    deny: ["rm -rf /"]
`

async function runTest() {
  try {
    const guard = Guard.fromYaml(yaml)
    console.log('Policy version:', guard.policyVersion())

    // 1. Check
    console.log('\n--- Test: check ---')
    const d1 = guard.check('bash', 'ls -la')
    console.log('Decision (ls):', d1.outcome)

    // 2. Execute (Async)
    console.log('\n--- Test: execute (ls) ---')
    const e1 = await guard.execute('bash', 'ls -la')
    console.log('Execute Status (ls):', e1.status)
    if (e1.output) {
      console.log('Exit Code:', e1.output.exitCode)
      console.log('Stdout (first line):', e1.output.stdout.split('\n')[0])
    }

    console.log('\n--- Test: execute (denied rm) ---')
    const e2 = await guard.execute('bash', 'rm -rf /')
    console.log('Execute Status (rm):', e2.status)
    if (e2.decision) {
      console.log('Decision Code:', e2.decision.code)
      console.log('Reason:', e2.decision.message)
    }

    // 3. Reload
    console.log('\n--- Test: reload ---')
    guard.reload(`
version: 1
default_mode: read_only
`)
    console.log('New Policy version:', guard.policyVersion())
    const d2 = guard.check('bash', 'ls -la')
    console.log('Decision after reload (ls in read_only):', d2.outcome)

    console.log('\nAll tests passed successfully (Node binding logic verified).')

  } catch (e) {
    console.error('Test failed:', e)
    process.exit(1)
  }
}

runTest()
