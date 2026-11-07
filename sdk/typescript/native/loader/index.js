/* eslint-disable */
// @ts-nocheck
'use strict'

const { bindingNotFound, wasiBindingNotFound } = require('./errors.js')
const { requireNative } = require('./native.js')
const { adoptTakenOverTarget, stampBindingTarget } = require('./stamp.js')
const { loadWasi } = require('./wasi.js')

// NAPI_RS_FORCE_WASI is a tri-state flag:
//   unset / any other value → native binding preferred, WASI is only a fallback
//   'true'                   → prefer WASI, but retain native as a lazy fallback
//   'error'                  → require WASI without initializing a native fallback
// Treating any non-empty string as truthy (the historical behavior) meant
// NAPI_RS_FORCE_WASI=false, NAPI_RS_FORCE_WASI=0, etc. inadvertently triggered the WASI
// path, causing ENOENT for packages shipped without a .wasi.cjs file.
//
// NAPI_RS_WASI_FLAVOR selects one exact generated flavor and implies strict WASI loading.
// It never crosses into another flavor or falls back to native.
function readMode(flavors) {
  const flavor = process.env.NAPI_RS_WASI_FLAVOR
  const requestedFlavor = typeof flavor === 'string' && flavor.length > 0 ? flavor : null
  if (requestedFlavor !== null && flavors.indexOf(requestedFlavor) === -1) {
    throw new Error('Unsupported WASI flavor "' + requestedFlavor + '". Available flavors: ' + flavors.join(', '))
  }
  const strictError = process.env.NAPI_RS_FORCE_WASI === 'error'
  return {
    requestedFlavor,
    strictError,
    forceWasi: process.env.NAPI_RS_FORCE_WASI === 'true' || strictError || requestedFlavor !== null,
  }
}

// A package without a WASI target still names the flavor it would report.
function wasiLayout({ binaryName, packageName }) {
  return {
    flavor: 'wasm32-wasi',
    local: `./${binaryName}.wasi.cjs`,
    artifacts: [`./${binaryName}.wasm32-wasi.debug.wasm`, `./${binaryName}.wasm32-wasi.wasm`],
    package: `${packageName}-wasm32-wasi`,
  }
}

function nativeBindingOf(ctx) {
  const binding = requireNative(ctx)
  ctx.state.required = binding
  return binding
}

// The binding to use once native failed or WASI was forced. A strict mode that finds no
// WASI binding throws; forced WASI without strictness falls back to native.
function bindingAfterWasi(ctx, mode, binding) {
  const loaded = loadWasi(ctx, mode.requestedFlavor)
  if (loaded) {
    return loaded.binding
  }
  if (mode.strictError || mode.requestedFlavor !== null) {
    throw wasiBindingNotFound(mode.requestedFlavor, ctx.wasiErrors)
  }
  return mode.forceWasi ? nativeBindingOf(ctx) : binding
}

// Loads the binding for this host and reports which artifact it is.
//
// `config` names the package: `require` (the entry's own, so every failure names the
// entry), `binaryName`, `packageName` and `version`. The caller stamps the target with
// `stampBindingTarget` before aliasing `module.exports` to the binding.
function loadBinding(config) {
  const wasi = wasiLayout(config)
  const flavors = [wasi.flavor]
  const ctx = {
    ...config,
    wasi,
    errors: [],
    wasiErrors: [],
    state: { target: 'native', required: null },
  }
  const mode = readMode(flavors)
  let binding = mode.forceWasi ? null : nativeBindingOf(ctx)
  if (!binding || mode.forceWasi) {
    binding = bindingAfterWasi(ctx, mode, binding)
  }
  if (!binding) {
    throw bindingNotFound(ctx.errors)
  }
  adoptTakenOverTarget(ctx.state, binding, flavors)
  return { binding, target: ctx.state.target }
}

module.exports = { loadBinding, stampBindingTarget }
