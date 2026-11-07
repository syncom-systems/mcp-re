# SPDX-License-Identifier: Apache-2.0
"""Selftest cases: requirements and license expressions with the verdict each must get, and the lock and advisory fixtures."""

from __future__ import annotations

#: (requirement, version, whether it matches)
MATCH_CASES = (
    (">= 1.2.3", "1.2.3", True), (">= 1.2.3", "1.2.2", False),
    ("^0.9.7", "0.9.9", True), ("^0.9.7", "0.10.0", False),
    ("^1.2", "1.9.0", True), ("^1.2", "2.0.0", False), ("^0.0.3", "0.0.4", False),
    ("~1.2.3", "1.2.9", True), ("~1.2.3", "1.3.0", False),
    (">= 1.0.0, < 1.4.2", "1.4.1", True), (">= 1.0.0, < 1.4.2", "1.4.2", False),
    ("> 1.2", "1.3.0", True), ("> 1.2", "1.2.9", False), ("<= 1.2", "1.2.7", True),
    ("= 0.2.1", "0.2.1", True), ("= 0.2.1", "0.2.2", False),
    (">= 1.0.0", "2.0.0-rc.1", False), (">= 2.0.0-rc.0", "2.0.0-rc.1", True),
    ("*", "7.1.0", True), ("1.2.3", "1.5.0", True),
)

LICENSE_ALLOW = {"MIT", "Apache-2.0", "ISC", "Apache-2.0 WITH LLVM-exception"}

#: (SPDX expression, whether the allow-list satisfies it)
LICENSE_CASES = (
    ("MIT", True), ("GPL-3.0", False), ("MIT OR GPL-3.0", True), ("GPL-3.0 OR MIT", True),
    ("Apache-2.0 AND ISC", True), ("Apache-2.0 AND GPL-3.0", False),
    ("(MIT OR GPL-3.0) AND ISC", True), ("(GPL-3.0 OR LGPL-2.1) AND MIT", False),
    ("Apache-2.0 WITH LLVM-exception", True), ("MIT WITH LLVM-exception", False),
    ("MIT/Apache-2.0", True), ("Apache-2.0+", True), ("", False),
)

#: A lock with an ambiguous name (`digest` at two versions), a git source and a dependency chain.
LOCK = ('version = 4\n'
        '[[package]]\nname = "ocsp"\nversion = "0.2.1"\nsource = "registry+R"\n'
        'dependencies = ["digest 0.10.7"]\n'
        '[[package]]\nname = "top"\nversion = "1.0.0"\nsource = "registry+R"\n'
        'dependencies = ["digest 0.11.0", "ocsp"]\n'
        '[[package]]\nname = "digest"\nversion = "0.10.7"\nsource = "registry+R"\n'
        '[[package]]\nname = "digest"\nversion = "0.11.0"\nsource = "registry+R"\n'
        '[[package]]\nname = "gitdep"\nversion = "0.1.0"\nsource = "git+https://x"\n')

#: An advisory page; `%s` takes extra `[advisory]` keys.
ADVISORY_DOC = ('```toml\n[advisory]\nid = "RUSTSEC-0000-0001"\npackage = "top"\ntitle = "t"\n'
                '%s\n[versions]\npatched = [">= 1.0.1"]\n```\n')

#: (extra `[advisory]` keys, advisories the check must report, ignored ids)
ADVISORY_CASES = (
    ("", 1, set()),
    ("", 0, {"RUSTSEC-0000-0001"}),
    ('informational = "unmaintained"', 1, set()),
    ('informational = "notice"', 0, set()),
    ('withdrawn = "2020-01-01"', 0, set()),
)

WILDCARD_SPEC = 'crate.spec(\n    package = "any",\n    version = "*",\n)\n'
