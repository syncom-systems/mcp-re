/* eslint-disable */
// @ts-nocheck
'use strict'

// The artifacts a platform/architecture may load, in the order they are tried. A value is
// a list, or a function of the libc probes for a platform whose artifact depends on them.

const isMingwNode = ({ config }) =>
  config?.variables?.shlib_suffix === 'dll.a' || config?.variables?.node_target_type === 'shared_library'

const byLibc = (musl, gnu) => ({ isMusl }) => [isMusl() ? musl : gnu]

const PLATFORMS = {
  android: {
    unsupported: 'Unsupported architecture on Android ',
    archs: { arm64: ['android-arm64'], arm: ['android-arm-eabi'] },
  },
  win32: {
    unsupported: 'Unsupported architecture on Windows: ',
    archs: {
      x64: (probes) => [isMingwNode(probes) ? 'win32-x64-gnu' : 'win32-x64-msvc'],
      ia32: ['win32-ia32-msvc'],
      arm64: ['win32-arm64-msvc'],
    },
  },
  darwin: {
    unsupported: 'Unsupported architecture on macOS: ',
    leading: ['darwin-universal'],
    archs: { x64: ['darwin-x64'], arm64: ['darwin-arm64'] },
  },
  freebsd: {
    unsupported: 'Unsupported architecture on FreeBSD: ',
    archs: { x64: ['freebsd-x64'], arm64: ['freebsd-arm64'], ppc64: ['freebsd-ppc64'] },
  },
  linux: {
    unsupported: 'Unsupported architecture on Linux: ',
    archs: {
      x64: byLibc('linux-x64-musl', 'linux-x64-gnu'),
      arm64: byLibc('linux-arm64-musl', 'linux-arm64-gnu'),
      arm: byLibc('linux-arm-musleabihf', 'linux-arm-gnueabihf'),
      loong64: byLibc('linux-loong64-musl', 'linux-loong64-gnu'),
      riscv64: byLibc('linux-riscv64-musl', 'linux-riscv64-gnu'),
      ppc64: ['linux-ppc64-gnu'],
      s390x: ['linux-s390x-gnu'],
    },
  },
  openharmony: {
    unsupported: 'Unsupported architecture on OpenHarmony: ',
    archs: { arm64: ['openharmony-arm64'], x64: ['openharmony-x64'], arm: ['openharmony-arm'] },
  },
}

const listFor = (entry, probes) => (typeof entry === 'function' ? entry(probes) : entry)

// What to try for this host: `suffixes` in order, then `unsupported` (an error message) when
// the platform is known but not the architecture, or the platform itself is unknown.
function selectTargets(platform, arch, probes) {
  const spec = Object.prototype.hasOwnProperty.call(PLATFORMS, platform) ? PLATFORMS[platform] : null
  if (!spec) {
    return { suffixes: [], unsupported: `Unsupported OS: ${platform}, architecture: ${arch}` }
  }
  const leading = spec.leading || []
  const entry = Object.prototype.hasOwnProperty.call(spec.archs, arch) ? spec.archs[arch] : null
  if (!entry) {
    return { suffixes: leading, unsupported: spec.unsupported + arch }
  }
  return { suffixes: leading.concat(listFor(entry, probes)), unsupported: null }
}

module.exports = { selectTargets }
