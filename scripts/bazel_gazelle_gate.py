#!/usr/bin/env python3
"""ADR-MCPS-048 / MCPS-70 — Bazel BUILD semantic-drift gate.

Governance boundary (the load-bearing rule): gazelle_rust ASSISTS and DETECTS
drift, but is NOT the authoritative owner of the committed BUILD files. This gate
enforces *semantic parity* over the managed target/edge set — NOT byte-identity,
NOT gazelle's formatting, NOT gazelle's exact generated text.

It runs `bazel run //:gazelle -- -mode diff` (which never writes) and inspects the
diff gazelle WOULD apply. It FAILS only on **unmanaged semantic drift the
developer forgot to add**:

  1. a target present in the Cargo graph but MISSING from BUILD (coverage drift —
     e.g. a `tests/*.rs` cargo runs with no Bazel target), and
  2. a first-party/third-party `deps` EDGE that a `use` implies but BUILD omits
     (the exact #220 failure: a missing first-party dep edge).

It deliberately IGNORES, as managed/allowed:

  * formatting gazelle injects: explicit `visibility`, `compile_data=["Cargo.toml"]`,
    and `deps` reordering (generate_from_cargo does these unconditionally);
  * `# keep` edges — the hand-pinned feature-flavor selections (MCPS-69);
  * edge REMOVALS — gazelle can't see non-code `data`/`compile_data` deps
    (source/spec/BUILD files the traceability manifest include_str!s) or
    platform-conditional deps; demanding their deletion would make gazelle the
    authority, which the ruling forbids. Removals are informational only;
  * allowlisted exceptions: HITL/live-cloud tests, platform-specific targets,
    naming collisions, and tracked known drift (see ALLOWLIST below).

Deterministic, read-only, no BUILD rewrites. Exit 0 = parity; exit 1 = drift.

Known limitation: a `deps` list expressed as an unmergeable form gazelle cannot
read — `all_crate_deps(...)`, a `_VAR + [...]` concat, or `glob(...)` for srcs —
is emitted by gazelle as a whole-attribute replacement, which this gate skips (it
is representation, not a clean inserted edge). Edges in such targets are therefore
not edge-gated. `all_crate_deps` is not used: it cannot load under the
spec-declared `crates_mcp_re` hub, which has no per-package Cargo tables. The
remaining unmergeable `deps` are three `_PROXY_LIB_DEPS + ...` concats in
`mcp-re-proxy/BUILD.bazel`; every other target uses an explicit `deps = [...]` list,
which gazelle merges — so a forgotten dep edge (the #220 failure) IS caught there.
Missing TARGETS are always caught regardless of deps representation.

CI: `python3 scripts/bazel_gazelle_gate.py` (pair with `bazel test //...`).
`--selftest` runs the drift classifier over hand-written diffs, with no Bazel.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bazel_gazelle.analyze import analyze_file  # noqa: E402,F401
from _bazel_gazelle.classify import classify  # noqa: E402,F401
from _bazel_gazelle.config import (  # noqa: E402,F401
    ALLOW_CARGO_ONLY_FIXTURE,
    ALLOW_HITL_LIVE,
    ALLOW_NAMING_COLLISION,
    ALLOW_NON_HERMETIC,
    ALLOW_TRACKED_DRIFT,
    ALLOW_UPSTREAM_REPRODUCER,
    ALLOWLIST,
    ATTR_OPEN_RE,
    FLAVOR_PLAIN,
    LABEL_TOKEN_RE,
    NAME_RE,
    NEW_TARGET_RE,
)
from _bazel_gazelle.diff import parse_per_file, run_gazelle_diff  # noqa: E402,F401
from _bazel_gazelle.report import main  # noqa: E402
from _bazel_gazelle.selftest import selftest  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(selftest() if "--selftest" in sys.argv else main())
