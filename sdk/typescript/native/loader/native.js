/* eslint-disable */
// @ts-nocheck
'use strict'

const { isMusl } = require('./libc.js')
const { selectTargets } = require('./targets.js')

const enforcesVersionCheck = () =>
  Boolean(process.env.NAPI_RS_ENFORCE_VERSION_CHECK) && process.env.NAPI_RS_ENFORCE_VERSION_CHECK !== '0'

// A load either yields `{ binding }` or records why it did not.
function attempt(load, errors) {
  try {
    return { binding: load() }
  } catch (e) {
    errors.push(e)
    return null
  }
}

function requirePackage(ctx, name) {
  const binding = ctx.require(name)
  const packageVersion = ctx.require(`${name}/package.json`).version
  if (packageVersion !== ctx.version && enforcesVersionCheck()) {
    throw new Error(`Native binding package version mismatch, expected ${ctx.version} but got ${packageVersion}. You can reinstall dependencies to fix this issue.`)
  }
  return binding
}

// The addon next to the loader first, then the platform package.
function attemptTarget(ctx, suffix) {
  const local = attempt(() => ctx.require(`./${ctx.binaryName}.${suffix}.node`), ctx.errors)
  return local || attempt(() => requirePackage(ctx, `${ctx.packageName}-${suffix}`), ctx.errors)
}

// The override may be a generated WASI loader, which already reports its own flavor.
// Adopt it: `module.exports` aliases the loaded object, so claiming 'native' would both
// misreport the artifact and overwrite the loader's marker through the alias.
function requireOverride(ctx, path) {
  return attempt(() => {
    const binding = ctx.require(path)
    ctx.state.target =
      binding && typeof binding.__napiBindingTarget === 'string' ? binding.__napiBindingTarget : 'native'
    return binding
  }, ctx.errors)
}

function requireHostTarget(ctx) {
  const probes = { isMusl, config: process.config }
  const { suffixes, unsupported } = selectTargets(process.platform, process.arch, probes)
  for (const suffix of suffixes) {
    const found = attemptTarget(ctx, suffix)
    if (found) {
      return found
    }
  }
  if (unsupported) {
    ctx.errors.push(new Error(unsupported))
  }
  return null
}

// The native binding, or undefined with every failure recorded in `ctx.errors`.
function requireNative(ctx) {
  const override = process.env.NAPI_RS_NATIVE_LIBRARY_PATH
  const found = override ? requireOverride(ctx, override) : requireHostTarget(ctx)
  return found ? found.binding : undefined
}

module.exports = { requireNative, enforcesVersionCheck }
