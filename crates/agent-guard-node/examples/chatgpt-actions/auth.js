'use strict'

const { timingSafeEqual } = require('node:crypto')

const API_KEY_ENV = 'CHATGPT_ACTIONS_API_KEY'
const MIN_API_KEY_LENGTH = 32

function loadRequiredApiKey(environment = process.env) {
  const apiKey = environment[API_KEY_ENV]
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    throw new Error(
      `${API_KEY_ENV} is required; generate a dedicated secret before starting the Action server`
    )
  }
  if (apiKey.length < MIN_API_KEY_LENGTH) {
    throw new Error(
      `${API_KEY_ENV} must contain at least ${MIN_API_KEY_LENGTH} characters`
    )
  }
  if (apiKey.trim() !== apiKey || /[\r\n]/u.test(apiKey)) {
    throw new Error(`${API_KEY_ENV} must not contain surrounding whitespace`)
  }
  return apiKey
}

function requestHasValidBearerToken(request, expectedApiKey) {
  const authorization = request.headers?.authorization
  if (
    typeof authorization !== 'string' ||
    !authorization.startsWith('Bearer ')
  ) {
    return false
  }

  const supplied = Buffer.from(authorization.slice('Bearer '.length), 'utf8')
  const expected = Buffer.from(expectedApiKey, 'utf8')
  return (
    supplied.length === expected.length && timingSafeEqual(supplied, expected)
  )
}

module.exports = {
  loadRequiredApiKey,
  requestHasValidBearerToken,
}
