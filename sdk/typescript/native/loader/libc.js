/* eslint-disable */
// @ts-nocheck
'use strict'

const { readFileSync } = require('fs')

const isFileMusl = (f) => f.includes('libc.musl-') || f.includes('ld-musl-')

const muslFromFilesystem = () => {
  try {
    return readFileSync('/usr/bin/ldd', 'utf-8').includes('musl')
  } catch {
    return null
  }
}

const diagnosticReport = () => {
  if (!(process.report && typeof process.report.getReport === 'function')) {
    return null
  }
  process.report.excludeNetwork = true
  return process.report.getReport() || null
}

const muslFromReport = () => {
  const report = diagnosticReport()
  if (!report) {
    return null
  }
  if (report.header && report.header.glibcVersionRuntime) {
    return false
  }
  return Array.isArray(report.sharedObjects) && report.sharedObjects.some(isFileMusl)
}

const muslFromChildProcess = () => {
  try {
    return require('child_process').execSync('ldd --version', { encoding: 'utf8' }).includes('musl')
  } catch (e) {
    // If we reach this case, we don't know if the system is musl or not, so is better to just fallback to false
    return false
  }
}

// Three probes, cheapest first; the first that has an answer decides.
function isMusl() {
  if (process.platform !== 'linux') {
    return false
  }
  const answer = muslFromFilesystem()
  if (answer !== null) {
    return answer
  }
  const fromReport = muslFromReport()
  return fromReport !== null ? fromReport : muslFromChildProcess()
}

module.exports = { isMusl }
