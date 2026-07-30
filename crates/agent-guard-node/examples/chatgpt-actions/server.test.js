'use strict'

const assert = require('node:assert/strict')
const { spawn } = require('node:child_process')
const { join } = require('node:path')
const test = require('node:test')

const API_KEY = '0123456789abcdef0123456789abcdef'
const serverPath = join(__dirname, 'server.js')

function startServer() {
  const child = spawn(process.execPath, [serverPath], {
    env: {
      ...process.env,
      CHATGPT_ACTIONS_API_KEY: API_KEY,
      PORT: '0',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  return new Promise((resolve, reject) => {
    let stderr = ''
    const timeout = setTimeout(() => {
      child.kill()
      reject(new Error(`timed out starting server: ${stderr}`))
    }, 15_000)

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8')
    })
    child.stdout.on('data', (chunk) => {
      const match = chunk
        .toString('utf8')
        .match(/listening on http:\/\/127\.0\.0\.1:(\d+)/u)
      if (match) {
        clearTimeout(timeout)
        resolve({
          child,
          baseUrl: `http://127.0.0.1:${match[1]}`,
        })
      }
    })
    child.once('exit', (code) => {
      clearTimeout(timeout)
      reject(new Error(`server exited before listening (${code}): ${stderr}`))
    })
  })
}

async function runShell(baseUrl, authorization) {
  const headers = { 'content-type': 'application/json' }
  if (authorization !== undefined) {
    headers.authorization = authorization
  }
  return fetch(`${baseUrl}/run-shell`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ command: 'echo authenticated' }),
  })
}

test('run-shell authenticates the caller before command handling', async (t) => {
  const { child, baseUrl } = await startServer()
  t.after(() => child.kill())

  const missing = await runShell(baseUrl)
  assert.equal(missing.status, 401)
  assert.equal((await missing.json()).message, 'authentication required')

  const wrong = await runShell(baseUrl, 'Bearer wrong-wrong-wrong-wrong-wrong')
  assert.equal(wrong.status, 401)

  const authenticated = await runShell(baseUrl, `Bearer ${API_KEY}`)
  assert.equal(authenticated.status, 200)
  assert.equal((await authenticated.json()).status, 'allowed')
})
