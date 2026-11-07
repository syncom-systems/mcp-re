# SPDX-License-Identifier: Apache-2.0
"""The selftest's hand-written workspace, MODULE.bazel specs, locks and cases."""

from __future__ import annotations

import json
from typing import NamedTuple

from _crate_spec_parity.config import CRATE_EXTENSION, REPIN_INPUTS, SPLICE_ROOT, UNSET


def dep(name: str, req: str, **opts) -> dict:
    """A dependency as the metadata reports it; `opts` overrides features, default,
    optional and path."""
    return {
        "name": name,
        "req": req,
        "features": list(opts.get("features", ())),
        "uses_default_features": opts.get("default", True),
        "optional": opts.get("optional", False),
        "path": opts.get("path"),
    }


def edit(text: str, old: str, new: str) -> str:
    if old not in text:
        raise SystemExit(f"SELFTEST FAILED: fixture edit anchor {old!r} not found")
    return text.replace(old, new)


META = {
    "packages": [
        {
            "dependencies": [
                dep("tokio", "^1", features=["rt"], default=False),
                dep("serde", "^1.0"),
                dep("vstd", "=0.0.1", optional=True),
                dep("local", "*", path="/x"),
            ]
        },
        {"dependencies": [dep("tokio", "^1", features=["macros"], default=False)]},
    ]
}
SERDE = 'crate.spec(\n    package = "serde",\n    version = "1.0",\n    repositories = ["h"],\n)\n'
TOKIO = (
    'crate.spec(\n    package = "tokio",\n    version = "1",\n    features = ["macros", "rt"],\n'
    '    default_features = False,\n    repositories = ["h"],\n)\n'
)
MODULE = SERDE + TOKIO
LOCK = (
    'version = 4\n\n[[package]]\nname = "tokio"\nversion = "1.2.3"\nchecksum = "aa"\n\n'
    f'[[package]]\nname = "{SPLICE_ROOT}"\nversion = "0.0.1"\n'
)
CARGO_LOCK = LOCK.replace(f'name = "{SPLICE_ROOT}"', 'name = "mcp-re-core"')


class SpecCase(NamedTuple):
    label: str
    module: str
    lock: str
    expect: str | None


SPEC_CASES: tuple[SpecCase, ...] = (
    SpecCase("the workspace and the specs agree", MODULE, LOCK, None),
    SpecCase(
        "a feature the workspace requests is missing",
        edit(MODULE, '"macros", ', ""),
        LOCK,
        "workspace only ['macros']",
    ),
    SpecCase(
        "a version requirement differs",
        edit(MODULE, 'version = "1",', 'version = "2",'),
        LOCK,
        "workspace 1, spec 2",
    ),
    SpecCase(
        "default features differ",
        edit(MODULE, "    default_features = False,\n", ""),
        LOCK,
        "default features",
    ),
    SpecCase("a spec no member requests", MODULE + edit(SERDE, "serde", "hyper"), LOCK, "`hyper`"),
    SpecCase("a spec is missing", TOKIO, LOCK, "`serde` and MODULE.bazel declares no spec"),
    SpecCase("the Bazel lock resolves another version", MODULE, edit(LOCK, "1.2.3", "1.2.4"), "tokio 1.2.4"),
    SpecCase(
        "the same version with another checksum",
        MODULE,
        edit(LOCK, '"aa"', '"bb"'),
        "different checksum",
    ),
    SpecCase("nothing was read", "", LOCK, "comparing nothing"),
)


def module_lock(repin: str, drop: bool = False) -> str:
    inputs = [f"ENV:{n} {repin if n == 'CARGO_BAZEL_REPIN' else UNSET}" for n in REPIN_INPUTS]
    return json.dumps(
        {"moduleExtensions": {CRATE_EXTENSION: {"general": {"recordedInputs": [] if drop else inputs}}}}
    )


REPIN_CASES: tuple[tuple[str, str, str | None], ...] = (
    ("repin inputs recorded unset", module_lock(UNSET), None),
    ("CARGO_BAZEL_REPIN recorded as 1", module_lock("1"), "ENV:CARGO_BAZEL_REPIN = '1'"),
    ("repin inputs not recorded", module_lock(UNSET, drop=True), "does not record"),
    ("not a lockfile", "{}", "comparing nothing"),
)
