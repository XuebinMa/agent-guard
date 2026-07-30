'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')
const {
  loadRequiredApiKey,
  requestHasValidBearerToken,
} = require('./auth')

const API_KEY = '0123456789abcdef0123456789abcdef'

test('ChatGPT Actions API key is mandatory and must be high entropy', () => {
  assert.throws(
    () => loadRequiredApiKey({}),
    /CHATGPT_ACTIONS_API_KEY.*required/
  )
  assert.throws(
    () => loadRequiredApiKey({ CHATGPT_ACTIONS_API_KEY: 'too-short' }),
    /at least 32/
  )
  assert.equal(
    loadRequiredApiKey({ CHATGPT_ACTIONS_API_KEY: API_KEY }),
    API_KEY
  )
})

test('run-shell authentication accepts only the exact Bearer token', () => {
  const request = (authorization) => ({
    headers: authorization === undefined ? {} : { authorization },
  })

  assert.equal(requestHasValidBearerToken(request(), API_KEY), false)
  assert.equal(
    requestHasValidBearerToken(request(`Bearer ${API_KEY}`), API_KEY),
    true
  )
  assert.equal(
    requestHasValidBearerToken(request(`bearer ${API_KEY}`), API_KEY),
    false
  )
  assert.equal(
    requestHasValidBearerToken(request(`Bearer ${API_KEY}x`), API_KEY),
    false
  )
  assert.equal(
    requestHasValidBearerToken(request('Basic Zm9vOmJhcg=='), API_KEY),
    false
  )
})
