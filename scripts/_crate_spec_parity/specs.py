# SPDX-License-Identifier: Apache-2.0
"""What the workspace requests, what MODULE.bazel declares, and what the locks resolve."""

from __future__ import annotations

import re
import tomllib

from _crate_spec_parity.config import BAZEL_ONLY_SPECS, SPEC_BLOCK, SPLICE_ROOT

Spec = tuple[str, frozenset[str], bool]


def requested(meta: dict) -> dict[str, Spec]:
    """What the workspace asks for, unified the way Cargo unifies one crate's requests."""
    out: dict[str, tuple[set[str], set[str], bool]] = {}
    for pkg in meta["packages"]:
        for dep in pkg["dependencies"]:
            if dep.get("path") or dep["optional"]:
                continue
            reqs, feats, default = out.get(dep["name"], (set(), set(), False))
            reqs.add(dep["req"].lstrip("^"))
            feats.update(dep["features"])
            out[dep["name"]] = (reqs, feats, default or dep["uses_default_features"])
    return {name: ("|".join(sorted(r)), frozenset(f), d) for name, (r, f, d) in out.items()}


def declared(module_text: str) -> dict[str, Spec]:
    out = {}
    for body in SPEC_BLOCK.findall(module_text):
        name = re.search(r'package = "([^"]+)"', body).group(1)
        version = re.search(r'version = "([^"]+)"', body).group(1)
        feats = re.search(r"features = \[([^\]]*)\]", body)
        features = frozenset(re.findall(r'"([^"]+)"', feats.group(1))) if feats else frozenset()
        out[name] = (version, features, "default_features = False" not in body)
    return out


def locked(lock_text: str) -> dict[tuple[str, str], str | None]:
    return {
        (p["name"], p["version"]): p.get("checksum")
        for p in tomllib.loads(lock_text).get("package", [])
    }


def bazel_only_packages(bazel_lock: str) -> set[str]:
    """The locked packages reachable ONLY through a Bazel-only spec — no Cargo lock can
    hold them, because no manifest requests the spec that pulls them in."""
    packages = tomllib.loads(bazel_lock).get("package", [])
    edges = {p["name"]: [d.split(" ")[0] for d in p.get("dependencies", [])] for p in packages}

    def reach(roots) -> set[str]:
        seen, stack = set(), list(roots)
        while stack:
            name = stack.pop()
            if name not in seen:
                seen.add(name)
                stack.extend(edges.get(name, []))
        return seen

    direct = edges.get(SPLICE_ROOT, [])
    return reach(set(direct) & set(BAZEL_ONLY_SPECS)) - reach(set(direct) - set(BAZEL_ONLY_SPECS))
