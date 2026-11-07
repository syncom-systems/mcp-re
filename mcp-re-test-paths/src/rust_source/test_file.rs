// SPDX-License-Identifier: Apache-2.0
//! The whole-file form of the test-region rule.

use super::brace_scan::BraceScan;

/// Whether the first line of `source` that carries code is the inner attribute
/// `#![cfg(test)]`, which makes the whole file test code.
///
/// The attribute is read with the same form rule as `opens_test_region`, one `!` further
/// in: `test` must be the whole first predicate or the first conjunct of `all(`. Anywhere
/// below the first code line the attribute is not a whole-file marker.
pub(super) fn is_test_file(source: &str) -> bool {
    let mut scan = BraceScan::new();
    for line in source.lines() {
        let code = scan.feed(line);
        let code = code.trim();
        if code.is_empty() {
            continue;
        }
        return code
            .strip_prefix("#![cfg(")
            .map(|rest| rest.strip_prefix("all(").unwrap_or(rest))
            .and_then(|rest| rest.strip_prefix("test"))
            .is_some_and(|after| {
                !after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            });
    }
    false
}
