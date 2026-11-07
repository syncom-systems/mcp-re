/* eslint-disable */
// @ts-nocheck
'use strict'

const describeError = (error) => {
  try {
    return error && typeof error.message === 'string' ? error.message : String(error)
  } catch {
    return 'Unknown error'
  }
}

// Each load failure becomes one link: the last error is the head and every earlier
// one hangs off `cause`.
function createLoadErrorChain(errors) {
  return errors.reduce((previous, current) => {
    const error = new Error(describeError(current))
    error.cause = previous
    return error
  }, null)
}

// assign `cause` instead of the `new Error(message, { cause })` options form, which
// Node < 16.9 silently ignores.
function bindingNotFound(loadErrors) {
  if (loadErrors.length === 0) {
    return new Error('Failed to load native binding')
  }
  const error = new Error(
    `Cannot find native binding. ` +
      `npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828). ` +
      'Please try `npm i` again after removing both package-lock.json and node_modules directory.',
  )
  error.cause = createLoadErrorChain(loadErrors)
  return error
}

function wasiBindingNotFound(flavor, wasiErrors) {
  const error = new Error(
    flavor
      ? 'WASI binding for flavor "' + flavor + '" not found'
      : 'WASI binding not found and NAPI_RS_FORCE_WASI is set to error',
  )
  error.cause = createLoadErrorChain(wasiErrors)
  return error
}

module.exports = { bindingNotFound, wasiBindingNotFound }
