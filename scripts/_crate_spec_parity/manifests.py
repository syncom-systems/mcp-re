# SPDX-License-Identifier: Apache-2.0
"""Reading the Cargo manifests and locks the way `cargo metadata` would report them."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from _crate_spec_parity.config import DEP_TABLES, EXTRA_WORKSPACES


def _dep_entries(manifest: dict):
    """(key, spec) for every dependency a manifest declares, in every table Cargo reads."""
    tables = [manifest.get(t, {}) for t in DEP_TABLES]
    for target in (manifest.get("target") or {}).values():
        tables += [target.get(t, {}) for t in DEP_TABLES]
    for table in tables:
        yield from table.items()


def _as_table(spec) -> dict:
    return {"version": spec} if isinstance(spec, str) else dict(spec)


def _dependency(key: str, spec, workspace_deps: dict) -> dict:
    """One dependency the way `cargo metadata` reports it: name, req, features, defaults."""
    spec = _as_table(spec)
    if spec.get("workspace") is True:
        inherited = _as_table(workspace_deps.get(key, {}))
        features = list(inherited.get("features", [])) + list(spec.get("features", []))
        spec = {
            **inherited,
            **{k: v for k, v in spec.items() if k != "workspace"},
            "features": features,
        }
    default = spec.get("default-features", spec.get("default_features", True))
    return {
        "name": spec.get("package", key),
        "req": str(spec.get("version", "*")),
        "features": list(spec.get("features", [])),
        "uses_default_features": default,
        "optional": bool(spec.get("optional", False)),
        "path": spec.get("path"),
    }


def _workspace_members(root: Path, ws: str) -> tuple[list[Path], dict]:
    """A workspace's member directories and its `[workspace.dependencies]`."""
    top = tomllib.loads((root / ws / "Cargo.toml").read_text())
    workspace = top.get("workspace", {})
    members = [root / ws / m for m in workspace.get("members", [])] or [root / ws]
    return members, workspace.get("dependencies", {})


def workspace_meta(root: Path) -> dict:
    """What `cargo metadata --no-deps` reported for the covered workspaces, read from the
    manifests themselves."""
    packages = []
    for ws in ("",) + EXTRA_WORKSPACES:
        members, workspace_deps = _workspace_members(root, ws)
        for member in members:
            manifest = tomllib.loads((member / "Cargo.toml").read_text())
            packages.append(
                {
                    "dependencies": [
                        _dependency(key, spec, workspace_deps)
                        for key, spec in _dep_entries(manifest)
                    ]
                }
            )
    return {"packages": packages}


def cargo_locks(root: Path) -> str:
    """Every covered workspace's lock, as one lock text (its packages concatenated)."""
    texts = [(root / ws / "Cargo.lock").read_text() for ws in ("",) + EXTRA_WORKSPACES]
    bodies = [re.sub(r"^version = \d+\s*$", "", t, flags=re.M) for t in texts]
    return "version = 4\n" + "\n".join(bodies)
