#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Supply-chain gate — `config/supply-chain.toml` over the crates Bazel builds.

The graph is the Bazel build graph, not a manifest's view of it: the third-party crates
`bazel query 'deps(//...)'` reaches through the `crates_mcp_re` hub, for the platforms
MODULE.bazel's crate universe supports. That is every crate the proxy, the SDK native
modules and the mock PKCS#11 provider compile — build-script and proc-macro dependencies
included — and nothing a platform we never build for would pull in. Each crate's version,
source and dependency edges come from `bazel/crates.lock`; its license from the manifest
Bazel fetched (the crate repository's `cargo_toml_env_vars` target).

Checks, each over that graph:

  * SOURCES     every crate comes from an allowed registry; none from git or elsewhere.
  * LICENSES    every crate's SPDX expression is satisfiable by the allow-list.
  * BANS        a `deny-multiple-versions` crate appears at one version (outside a
                `skip-tree` subtree); a `crate.spec` is never `*`. Other duplicates are
                listed, not failed.
  * ADVISORIES  no crate version is affected by a RustSec vulnerability, unmaintained or
                unsound advisory (not withdrawn, not in `ignore`), and none is yanked
                on crates.io.

ADVISORIES needs the network: the RustSec database (`--advisory-db`, a checkout of
github.com/rustsec/advisory-db) and the crates.io sparse index. The workflow runs it
daily, because the database moves independently of this repository.

    python3 scripts/supply_chain_gate.py --advisory-db DIR   # the verdict
    python3 scripts/supply_chain_gate.py --selftest          # prove each check can FAIL
    python3 scripts/supply_chain_gate.py --list              # crate, version, license
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _supply_chain.checks import (  # noqa: E402,F401
    advisory,
    affected,
    check_advisories,
    check_bans,
    check_licenses,
    check_policy_keys,
    check_sources,
    skipped,
)
from _supply_chain.cli import inventory, verdict  # noqa: E402
from _supply_chain.config import (  # noqa: E402,F401
    DENIED_CLASSES,
    HUB,
    INDEX,
    LOCK,
    MODULE,
    POLICY,
    POLICY_KEYS,
    REPO,
)
from _supply_chain.graph import (  # noqa: E402,F401
    bazel,
    build_graph,
    crate_licenses,
    lock_packages,
    repo_key,
    resolve_edges,
)
from _supply_chain.index import check_yanked, index_path, yanked_versions  # noqa: E402,F401
from _supply_chain.selftest import selftest  # noqa: E402,F401
from _supply_chain.semver import matches, parse_version  # noqa: E402,F401
from _supply_chain.spdx import license_allowed  # noqa: E402,F401


def main() -> int:
    ap = argparse.ArgumentParser(description="supply-chain gate over the Bazel build graph")
    ap.add_argument("--advisory-db", type=Path, help="a checkout of github.com/rustsec/advisory-db")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--list", action="store_true", help="print the graph's crates and licenses")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.list:
        return inventory()
    if a.advisory_db is None:
        ap.error("--advisory-db is required: the advisory check is part of the verdict")
    return verdict(a.advisory_db)


if __name__ == "__main__":
    sys.exit(main())
