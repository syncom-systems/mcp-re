// SPDX-License-Identifier: Apache-2.0
//
// Render the committed napi loader and declarations from the type definitions Bazel
// collected (//sdk/typescript:native_type_defs):
//
//   node scripts/write-binding.mjs <type-defs dir> [<output dir>]
//
// The declarations are the pinned @napi-rs/cli's own — `generateTypeDef`, called with what
// its `build --platform --dts binding.d.ts` passes — so they are byte-for-byte what that
// build wrote. The loader entry is rendered by render-binding.mjs over the hand-written
// native/loader/ modules, not by the CLI's `writeJsBinding`: its single `requireNative`
// is a 487-line branch per platform that nothing could review or test. Only the compile
// step moved to Bazel.
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { generateTypeDef, readNapiConfig } from '@napi-rs/cli'

import { renderBinding } from './render-binding.mjs'

const BINDING_TARGET_EXPORT = '__napiBindingTarget'

const [typeDefDir, outArg] = process.argv.slice(2)
if (!typeDefDir) {
  console.error('usage: write-binding.mjs <type-defs dir> [<output dir>]')
  process.exit(2)
}
const cwd = resolve(fileURLToPath(new URL('..', import.meta.url)))
const outputDir = resolve(outArg ?? join(cwd, 'native'))
const config = await readNapiConfig(join(cwd, 'package.json'))
if (config.targets.some((t) => t.platform === 'wasi')) {
  throw new Error('a WASI target changes the loader the CLI renders; this script renders none')
}

// The CLI's predicate for a --platform build with a root loader and no WASI fallback.
const declareBindingTarget = (exports) => exports.length > 0
const { exports, dts } = await generateTypeDef({
  typeDefDir: resolve(typeDefDir),
  configDtsHeader: config.dtsHeader,
  configDtsHeaderFile: config.dtsHeaderFile,
  constEnum: config.constEnum,
  runtimeStringEnum: config.runtimeStringEnum,
  cwd,
  declareBindingTarget,
})
if (exports.length === 0) {
  throw new Error(`no napi export in ${typeDefDir}: the type definitions were not collected`)
}
if (declareBindingTarget(exports) && exports.includes(BINDING_TARGET_EXPORT)) {
  throw new Error(`\`${BINDING_TARGET_EXPORT}\` is reserved by the generated binding loader`)
}

await mkdir(outputDir, { recursive: true })
await writeFile(join(outputDir, 'binding.d.ts'), dts, 'utf-8')
await writeFile(
  join(outputDir, 'binding.js'),
  renderBinding({
    binaryName: config.binaryName,
    packageName: config.packageName,
    version: config.packageJson.version,
    idents: exports,
  }),
  'utf-8',
)
console.log(`write-binding: ${exports.length} export(s) -> ${outputDir}/binding.{js,d.ts}`)
