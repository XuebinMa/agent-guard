const { Guard } = require('./index.js')

const yaml = `
version: 1
default_mode: workspace_write
rules:
  - tool: bash
    allow: ["ls"]
    deny: ["rm -rf /"]
`

try {
  const guard = Guard.fromYaml(yaml)
  console.log('Policy version:', guard.policyVersion())

  const d1 = guard.check('bash', JSON.stringify({ command: 'ls -la' }))
  console.log('Decision 1 (ls):', d1.outcome)

  const d2 = guard.check('bash', JSON.stringify({ command: 'rm -rf /' }))
  console.log('Decision 2 (rm):', d2.outcome)

  // Test Context
  const d3 = guard.check('bash', JSON.stringify({ command: 'rm -rf /' }), {
    trust_level: 'admin'
  })
  console.log('Decision 3 (admin rm):', d3.outcome)

} catch (e) {
  console.error('Test failed:', e)
  process.exit(1)
}
