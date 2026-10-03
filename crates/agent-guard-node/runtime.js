'use strict'

const nativeApi = require('./index.js')
const { createAdapterExports, fallbackNormalizePayload } = require('./adapters.js')

const adapterExports = createAdapterExports({
  TrustLevel: nativeApi.TrustLevel,
  normalizePayload: nativeApi.normalizePayload,
})

const exportedNormalizePayload =
  typeof nativeApi.normalizePayload === 'function'
    ? nativeApi.normalizePayload
    : fallbackNormalizePayload

const exportedVerifyReceipt =
  typeof nativeApi.verifyReceipt === 'function'
    ? nativeApi.verifyReceipt
    : function missingVerifyReceipt() {
        throw new Error('verifyReceipt is unavailable in the current native binding')
      }

module.exports = {
  ...nativeApi,
  normalizePayload: exportedNormalizePayload,
  verifyReceipt: exportedVerifyReceipt,
  ...adapterExports,
}

// Keep CommonJS consumers on the object above while exposing statically
// discoverable names for Node ESM `import { ... }` interop. Object spreads are
// not visible to Node's CommonJS export lexer.
module.exports.TrustLevel = nativeApi.TrustLevel
module.exports.Guard = nativeApi.Guard
module.exports.normalizePayload = exportedNormalizePayload
module.exports.verifyReceipt = exportedVerifyReceipt
module.exports.AgentGuardAdapterError = adapterExports.AgentGuardAdapterError
module.exports.AgentGuardDeniedError = adapterExports.AgentGuardDeniedError
module.exports.AgentGuardAskRequiredError = adapterExports.AgentGuardAskRequiredError
module.exports.AgentGuardExecutionError = adapterExports.AgentGuardExecutionError
module.exports.createGuardedExecutor = adapterExports.createGuardedExecutor
module.exports.wrapLangChainTool = adapterExports.wrapLangChainTool
module.exports.wrapOpenAITool = adapterExports.wrapOpenAITool
