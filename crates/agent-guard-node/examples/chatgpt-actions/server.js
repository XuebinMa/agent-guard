'use strict'

const { createServer } = require('http')
const { readFileSync } = require('fs')
const { join } = require('path')
const {
  Guard,
  wrapOpenAITool,
  AgentGuardDeniedError,
  AgentGuardAskRequiredError,
} = require('../..')

const port = Number(process.env.PORT || 8787)
const policyPath = join(__dirname, 'policy.yaml')
const policyYaml = readFileSync(policyPath, 'utf8')
const guard = Guard.fromYaml(policyYaml)

const guardedShell = wrapOpenAITool(
  guard,
  async () => {
    throw new Error('Original shell handler should not run in enforce mode')
  },
  {
    tool: 'bash',
    mode: 'enforce',
    trustLevel: 'Trusted',
    agentId: 'chatgpt-actions-demo',
    actor: 'chatgpt-user',
    workingDirectory: () => process.cwd(),
    resultMapper: (outcome) => outcome.output?.stdout.trim() ?? '',
  }
)

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type',
  })
  response.end(JSON.stringify(body, null, 2))
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let raw = ''
    request.on('data', (chunk) => {
      raw += chunk.toString('utf8')
    })
    request.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {})
      } catch (error) {
        reject(error)
      }
    })
    request.on('error', reject)
  })
}

const server = createServer(async (request, response) => {
  if (!request.url) {
    sendJson(response, 400, { status: 'error', message: 'missing request url' })
    return
  }

  if (request.method === 'OPTIONS') {
    sendJson(response, 200, { ok: true })
    return
  }

  if (request.method === 'GET' && request.url === '/health') {
    sendJson(response, 200, {
      ok: true,
      policyVersion: guard.policyVersion(),
    })
    return
  }

  if (request.method === 'POST' && request.url === '/run-shell') {
    let body
    try {
      body = await readJson(request)
    } catch (error) {
      sendJson(response, 400, {
        status: 'error',
        message: `invalid json body: ${error.message}`,
      })
      return
    }

    const command = typeof body.command === 'string' ? body.command : ''
    if (!command) {
      sendJson(response, 400, {
        status: 'error',
        message: 'request body must include a non-empty "command" string',
      })
      return
    }

    try {
      const result = await guardedShell({ command })
      sendJson(response, 200, {
        status: 'allowed',
        result,
      })
    } catch (error) {
      if (
        error instanceof AgentGuardDeniedError ||
        error instanceof AgentGuardAskRequiredError
      ) {
        sendJson(response, 200, {
          status: 'blocked',
          error: error.name,
          decision: error.decision,
          code: error.code,
          message: error.askPrompt || error.message,
        })
        return
      }

      sendJson(response, 500, {
        status: 'error',
        message: error instanceof Error ? error.message : String(error),
      })
    }
    return
  }

  sendJson(response, 404, {
    status: 'error',
    message: 'route not found',
  })
})

server.listen(port, '127.0.0.1', () => {
  console.log(`ChatGPT Actions demo server listening on http://127.0.0.1:${port}`)
  console.log(`Policy version: ${guard.policyVersion()}`)
})
