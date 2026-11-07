/* eslint-disable */
// @ts-nocheck
'use strict'

const { enforcesVersionCheck } = require('./native.js')

const isNotFound = (error) => Boolean(error) && error.code === 'MODULE_NOT_FOUND'

// Null when `specifier` resolves, the MODULE_NOT_FOUND error when it does not; any other
// resolution failure is a real fault and propagates.
function resolutionFailure(resolve, specifier) {
  try {
    resolve(specifier)
    return null
  } catch (error) {
    if (!isNotFound(error)) {
      throw error
    }
    return error
  }
}

// A package that is missing is a candidate failure; one that exists but cannot be
// resolved is a fault. An exports restriction proves the package exists even when its
// package.json is not public, so only a missing package.json counts as missing.
function missingPackageFailure(resolve, specifier, rootError) {
  try {
    resolve(specifier + '/package.json')
  } catch (packageError) {
    if (isNotFound(packageError)) {
      return rootError
    }
  }
  throw rootError
}

function artifactFailure(resolve, artifacts) {
  let failure = null
  for (const artifact of artifacts) {
    failure = resolutionFailure(resolve, artifact)
    if (failure === null) {
      return null
    }
  }
  return failure
}

function candidateFailure(resolve, candidate) {
  const rootError = resolutionFailure(resolve, candidate.specifier)
  if (rootError !== null) {
    return candidate.isPackage ? missingPackageFailure(resolve, candidate.specifier, rootError) : rootError
  }
  return candidate.artifacts ? artifactFailure(resolve, candidate.artifacts) : null
}

function requireWasiPackage(ctx, name) {
  if (enforcesVersionCheck()) {
    const packageVersion = ctx.require(`${name}/package.json`).version
    if (packageVersion !== ctx.version) {
      throw new Error(`WASI binding package version mismatch, expected ${ctx.version} but got ${packageVersion}. You can reinstall dependencies to fix this issue.`)
    }
  }
  return ctx.require(name)
}

function wasiCandidates(wasi) {
  return [
    {
      specifier: wasi.local,
      isPackage: false,
      artifacts: wasi.artifacts,
      load: (ctx) => ctx.require(wasi.local),
    },
    {
      specifier: wasi.package,
      isPackage: true,
      artifacts: undefined,
      load: (ctx) => requireWasiPackage(ctx, wasi.package),
    },
  ]
}

// One candidate: `{ binding }` when it loaded, null when it failed; the failure is
// recorded in both error lists.
function tryCandidate(ctx, candidate) {
  let failure
  try {
    const resolveFailure = candidateFailure((s) => ctx.require.resolve(s), candidate)
    if (resolveFailure === null) {
      return { binding: candidate.load(ctx) }
    }
    failure = resolveFailure
  } catch (err) {
    failure = err
  }
  ctx.wasiErrors.push(failure)
  ctx.errors.push(failure)
  return null
}

// The WASI fallback chain: the generated loader, then the WASI package. A requested
// flavor other than this package's own tries nothing.
function loadWasi(ctx, requestedFlavor) {
  const { wasi } = ctx
  if (requestedFlavor && requestedFlavor !== wasi.flavor) {
    return null
  }
  for (const candidate of wasiCandidates(wasi)) {
    const loaded = tryCandidate(ctx, candidate)
    if (loaded) {
      ctx.state.target = wasi.flavor
      return loaded
    }
  }
  return null
}

module.exports = { loadWasi }
