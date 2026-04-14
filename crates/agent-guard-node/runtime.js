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
