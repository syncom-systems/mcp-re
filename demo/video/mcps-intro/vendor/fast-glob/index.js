// SPDX-License-Identifier: Apache-2.0
//
// @motion-canvas/vite-plugin calls exactly two fast-glob functions, `isDynamicPattern` and
// `sync(pattern, { onlyFiles: true })`, to expand its `project` option. This package provides
// those two over tinyglobby, which matches with picomatch and does not depend on braces.
'use strict';

const { globSync, isDynamicPattern } = require('tinyglobby');

function sync(patterns, options = {}) {
  return globSync(patterns, {
    cwd: options.cwd,
    absolute: options.absolute === true,
    dot: options.dot === true,
    onlyFiles: options.onlyFiles !== false,
    ignore: options.ignore,
    expandDirectories: false,
  });
}

module.exports = { sync, isDynamicPattern };
