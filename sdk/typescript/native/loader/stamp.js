/* eslint-disable */
// @ts-nocheck
'use strict'

const TARGET_KEY = '__napiBindingTarget'

const hasTarget = (exportsObject) => Object.prototype.hasOwnProperty.call(exportsObject, TARGET_KEY)

function conflictError() {
  const error = new Error(
    '`__napiBindingTarget` is reserved by the generated binding loader, but the loaded binding already exports it. Rename the export, e.g. #[napi(js_name = "...")].',
  )
  error.code = 'ERR_NAPI_BINDING_TARGET_CONFLICT'
  return error
}

// [[Define]], not [[Set]]: an ordinary assignment walks the prototype chain, so an
// inherited accessor could swallow the value or throw and fail an otherwise successful
// load. The descriptor is what a successful assignment would have produced. Reporting the
// artifact is metadata, never a reason to fail a load: an exotic object (a Proxy whose
// defineProperty trap refuses) is skipped, not thrown over.
function defineTarget(exportsObject, target) {
  try {
    Object.defineProperty(exportsObject, TARGET_KEY, {
      configurable: true,
      enumerable: true,
      value: target,
      writable: true,
    })
  } catch {
    // skipped, see above
  }
}

// Marks the loaded binding with the artifact it came from and returns the target.
//
// - Already ours: the root entry aliases the object it loaded, so a WASI fallback
//   candidate, or a `NAPI_RS_NATIVE_LIBRARY_PATH` override that is a generated loader,
//   arrives already stamped with this same value.
// - Another value: the addon's own export claims the reserved name, which is refused.
// - Not extensible: a `#[napi(module_exports)]` hook may seal or freeze the object, and
//   the stamp is skipped. The CommonJS entries hand back this very object as
//   `module.exports`, so there the value is then absent.
//
// The CommonJS entry assigns the return value so `cjs-module-lexer`, and therefore Node's
// CJS -> ESM named export detection, sees `__napiBindingTarget` statically.
function stampBindingTarget(exportsObject, target) {
  if (hasTarget(exportsObject)) {
    if (exportsObject[TARGET_KEY] !== target) {
      throw conflictError()
    }
    return target
  }
  if (Object.isExtensible(exportsObject)) {
    defineTarget(exportsObject, target)
  }
  return target
}

// The flavor an own data property claims, or null: it must be one of `flavors` and read
// back through the property as the descriptor states.
function takenOverFlavor(binding, flavors) {
  const descriptor = Object.getOwnPropertyDescriptor(binding, TARGET_KEY)
  if (!descriptor || flavors.indexOf(descriptor.value) === -1) {
    return null
  }
  return binding[TARGET_KEY] === descriptor.value ? descriptor.value : null
}

// A package can patch its own fallback in front of the load-failure check, e.g. a
// WebContainer download through `napi-postinstall/fallback`. That fallback swaps the
// binding for a generated WASI loader, which has already stamped its own flavor, while the
// loader's target still says 'native'. Take that flavor over, or the stamp throws a
// conflict and the ESM export reports the wrong artifact. Three limits keep the conflict
// check:
// - only a binding this loader did not load itself, so a native addon whose
//   `#[napi(module_exports)]` hook claims the name is still rejected;
// - only an own data property, read through its descriptor, so no addon getter runs here,
//   and it must read back the same, as the stamp reads it;
// - only a flavor this loader's own WASI chain can report.
// This is metadata and never fails a load: a throwing Proxy trap keeps 'native'.
function adoptTakenOverTarget(state, binding, flavors) {
  if (state.target !== 'native' || binding === state.required) {
    return
  }
  try {
    const flavor = takenOverFlavor(binding, flavors)
    if (flavor !== null) {
      state.target = flavor
    }
  } catch {
    // keep 'native'
  }
}

module.exports = { stampBindingTarget, adoptTakenOverTarget }
