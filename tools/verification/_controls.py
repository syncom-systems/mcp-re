# SPDX-License-Identifier: Apache-2.0
"""Every executable verification control the tree holds — ADR-MCPRE-069 §2.

ADR-MCPRE-069 asks a question ADR-MCPRE-059's registry never asks: *which controls run and
are claimed by nothing?* Answering it needs one thing the registry cannot supply — the set
of controls that EXIST — and that set has to be measured from the tree, in the same
vocabulary the registry names its evidence in, or the join between them is a guess.

# Identity is the selector, not the function name

A control's identity names the thing that exists in SOURCE, inside its project: for Rust,
`<crate root>#module::path::fn` — `src/lib.rs#cli::tests::x`, `tests/integration/main.rs#y`,
`src/main.rs#startup::tests::z` — with the root relative to its Bazel package; `doc#item`
for a rustdoc example; `pytest#file::fn`; `vitest#file > suite > name`. A selector joins to
it by resolving its test target's crate root (`_census`), so a name-only join — `fn`
without its root — cannot report a control as claimed because an unrelated crate happens to
have a test of the same name.

The crate root, not the test target, because a crate compiled in several flavors — the
same sources under different features — is one module tree: a test in it is ONE control,
however many test binaries compile it, and a unit selects it through whichever flavor's
target builds the configuration its claim is about.

# The Rust module path is FOLLOWED, never derived from the file path

`mcp-re-client/src/startup.rs` is `src/main.rs#startup`, because `main.rs` declares it and
`lib.rs` does not. Deriving the module path from the directory layout gets that wrong in
both directions — it invents controls in a root that never compiles them, and it misses
every control a binary owns. So each crate ROOT the build graph compiles into a test is
walked: `mod name;` is resolved to its file, `#[path = "..."]` is honoured, and an inline
`mod name { … }` nests in place.

A file reachable from two roots yields two controls, and that is not double counting: the
same source function compiled into the library's module tree and into an integration
target's are two things libtest can run and two things a unit can select, and exactly one of
them may be the claimed one.

# What counts as a control kind here

Everything with an executable carrier that a unit could name as evidence, plus the two
registries whose entries are executed by their own lanes:

  * `rust-test`      — `#[test]` / `#[tokio::test]`, per target
  * `rust-doctest`   — a rustdoc example, including the `compile_fail` ones ADR-069 §2.1
                       records as invisible to the first census
  * `pytest`         — a collected pytest function
  * `vitest`         — a registered `it(…)` / `test(…)` case
  * `structural`     — a `[[probe]]` in `structural-probes.toml`
  * `mutation`       — a `[[probe]]` in `mutation-probes.toml`
  * `measurement`    — a `[[measurement]]` in `measurements.toml`
  * `gate`           — an executable check under `scripts/` that a lane runs

The list is derived from the execution machinery that exists, and `KINDS` is its single
statement. A kind nothing can run does not belong here; a kind that runs and is absent
makes every "0 unclaimed" this module supports a false green, which is why
`test_controls.py` holds a positive-scope control per kind.
"""

from __future__ import annotations

import json

from _control_doctest import doctest_controls
from _control_files import walk
from _control_model import KINDS, Control
from _control_pytest import pytest_controls
from _control_registry import gate_controls, probe_controls
from _control_rust import rust_controls
from _control_vitest import vitest_controls
from _ecosystems import REPO_ROOT

__all__ = [
    "KINDS",
    "REPO_ROOT",
    "Control",
    "all_controls",
    "doctest_controls",
    "gate_controls",
    "main",
    "probe_controls",
    "pytest_controls",
    "rust_controls",
    "vitest_controls",
    "walk",
]


def all_controls() -> list[Control]:
    """Every control of every kind, sorted by identity.

    Sorted so that two runs over the same tree produce the same report in the same order:
    a census whose output depends on filesystem iteration order cannot be diffed, and a
    report nobody can diff is a report nobody reads twice.
    """
    controls = (
        rust_controls()
        + doctest_controls()
        + pytest_controls()
        + vitest_controls()
        + probe_controls()
        + gate_controls()
    )
    return sorted(controls, key=lambda c: (c.kind, c.identity))


def main() -> int:
    controls = all_controls()
    by_kind: dict[str, int] = {}
    for control in controls:
        by_kind[control.kind] = by_kind.get(control.kind, 0) + 1
    print(json.dumps({"total": len(controls), "by_kind": by_kind}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
