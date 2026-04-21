'use strict'

const http = require('http')
const { mkdtempSync, readFileSync } = require('fs')
const { tmpdir } = require('os')
const { join } = require('path')

const { Guard } = require('..')

function startServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => {
        res.statusCode = 202
        res.end(`accepted:${body}`)
      })
    })
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(server))
  })
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

async function main() {
  const workspace = mkdtempSync(join(tmpdir(), 'agent-guard-wedge-'))
  const server = await startServer()
  const { port } = server.address()
  const allowedUrl = `http://127.0.0.1:${port}/publish`
  const artifactPath = join(workspace, 'release-summary.txt')

  const guard = Guard.fromYaml(`
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - prefix: "echo summary:"
  write_file:
    allow_paths:
      - "${workspace}/**"
  http_request:
    ask:
      - prefix: "https://api.example.com/"
`)

  try {
    const shellPayload = JSON.stringify({ command: 'echo summary:release-ready' })
    const shellDecision = guard.decide('bash', shellPayload)
    const shellOutcome = await guard.run('bash', shellPayload)

    const filePayload = JSON.stringify({
      path: artifactPath,
      content: shellOutcome.output.stdout.trim(),
    })
    const fileDecision = guard.decide('write_file', filePayload)
    const fileOutcome = await guard.run('write_file', filePayload)

    const httpPayload = JSON.stringify({
      method: 'POST',
      url: allowedUrl,
      body: readFileSync(artifactPath, 'utf8'),
    })
    const httpDecision = guard.decide('http_request', httpPayload)
    const httpOutcome = await guard.run('http_request', httpPayload)

    const approvalPayload = JSON.stringify({
      method: 'POST',
      url: 'https://api.example.com/publish',
      body: '{"release":"candidate"}',
    })
    const approvalDecision = guard.decide('http_request', approvalPayload)
    const approvalOutcome = await guard.run('http_request', approvalPayload)

    console.log('=== agent-guard side-effect wedge ===')
    console.log('')
    console.log(`[1] shell decision: ${shellDecision.outcome}`)
    console.log(`[1] shell output: ${shellOutcome.output.stdout.trim()}`)
    console.log('')
    console.log(`[2] file decision: ${fileDecision.outcome}`)
    console.log(`[2] file path: ${artifactPath}`)
    console.log(`[2] file contents: ${readFileSync(artifactPath, 'utf8')}`)
    console.log(`[2] file status: ${fileOutcome.status}`)
    console.log('')
    console.log(`[3] http decision: ${httpDecision.outcome}`)
    console.log(`[3] http response: ${httpOutcome.output.stdout}`)
    console.log('')
    console.log(`[4] remote publish decision: ${approvalDecision.outcome}`)
    console.log(`[4] remote publish status: ${approvalOutcome.status}`)
    console.log(`[4] remote publish prompt: ${approvalOutcome.decision.askPrompt}`)
  } finally {
    await closeServer(server)
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
