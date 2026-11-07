# SPDX-License-Identifier: Apache-2.0
"""The checks over the graph: policy keys, sources, licenses, bans and RustSec advisories."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from _supply_chain.config import DENIED_CLASSES, POLICY_KEYS
from _supply_chain.graph import Key
from _supply_chain.semver import matches, parse_version, version_key
from _supply_chain.spdx import license_allowed


def check_policy_keys(policy: dict) -> list[str]:
    problems = [f"POLICY: unknown section [{s}]" for s in policy if s not in POLICY_KEYS]
    for section, keys in POLICY_KEYS.items():
        problems += [f"POLICY: [{section}] {k} is not a key this gate enforces"
                     for k in policy.get(section, {}) if k not in keys]
    return problems


def check_sources(graph: list[Key], packages: dict, allowed: list[str]) -> list[str]:
    ok = {f"registry+{r}" for r in allowed}
    return [f"SOURCES: {n} {v} comes from {packages[(n, v)].get('source') or 'no recorded source'}"
            for n, v in graph if packages[(n, v)].get("source") not in ok]


def _license_problem(n: str, v: str, expr: str | None, allow: set[str]) -> str | None:
    if expr is None:
        return f"LICENSES: {n} {v}: no manifest license was read"
    if not expr:
        return f"LICENSES: {n} {v} declares no SPDX license expression"
    if not license_allowed(expr, allow):
        return f"LICENSES: {n} {v} is `{expr}`, which the allow-list does not satisfy"
    return None


def check_licenses(graph: list[Key], licenses: dict[str, str], allow: set[str]) -> list[str]:
    found = (_license_problem(n, v, licenses.get(f"{n}-{v}"), allow) for n, v in graph)
    return [problem for problem in found if problem is not None]


def _walk_skip_tree(tree: dict, edges: dict, graph: set[Key], out: set[Key]) -> None:
    """Add to `out` the crates within `tree["depth"]` edges of the tree's root versions."""
    roots = [k for k in graph if k[0] == tree["name"] and matches("=" + tree["version"], k[1])]
    frontier = [(r, 0) for r in roots]
    while frontier:
        node, depth = frontier.pop()
        if node in out or depth > tree["depth"]:
            continue
        out.add(node)
        frontier += [(d, depth + 1) for d in edges.get(node, [])]


def skipped(skip_trees: list[dict], edges: dict, graph: set[Key]) -> set[Key]:
    out: set[Key] = set()
    for tree in skip_trees:
        _walk_skip_tree(tree, edges, graph, out)
    return out


def _versions_by_crate(graph: list[Key], exempt: set[Key]) -> dict[str, set[str]]:
    versions: dict[str, set[str]] = {}
    for n, v in graph:
        if (n, v) not in exempt:
            versions.setdefault(n, set()).add(v)
    return versions


def _duplicate_lines(versions: dict[str, set[str]]) -> list[tuple[str, str]]:
    """(crate, '<crate>: <versions>') for every crate present at more than one version."""
    return [(name, f"{name}: {', '.join(sorted(vs, key=lambda x: version_key(parse_version(x))))}")
            for name, vs in sorted(versions.items()) if len(vs) >= 2]


def _wildcard_problem(body: str) -> str | None:
    if not re.search(r'version = "\*"', body):
        return None
    name = re.search(r'package = "([^"]+)"', body)
    return f"BANS: crate.spec `{name.group(1) if name else body.strip()}` requires version `*`"


def _wildcard_problems(module_text: str) -> list[str]:
    bodies = re.findall(r"^crate\.spec\((.*?)^\)", module_text, re.M | re.S)
    return [problem for problem in map(_wildcard_problem, bodies) if problem is not None]


def check_bans(graph: list[Key], edges: dict, bans: dict, module_text: str) -> tuple[list[str], list[str]]:
    exempt = skipped(bans.get("skip-tree", []), edges, set(graph))
    duplicates = _duplicate_lines(_versions_by_crate(graph, exempt))
    denied = bans.get("deny-multiple-versions", [])
    problems = [f"BANS: more than one version of a single-version crate — {line}"
                for name, line in duplicates if name in denied]
    notes = [line for name, line in duplicates if name not in denied]
    if bans.get("deny-wildcard-specs"):
        problems += _wildcard_problems(module_text)
    return problems, notes


def advisory(text: str) -> dict:
    body = re.search(r"```toml\n(.*?)\n```", text, re.S)
    return tomllib.loads(body.group(1)) if body else {}


def affected(adv: dict, version: str) -> bool:
    reqs = adv.get("versions", {})
    return not any(matches(r, version) for r in reqs.get("patched", []) + reqs.get("unaffected", []))


def _is_denied(meta: dict, ignore: set[str]) -> bool:
    """An advisory that counts: not withdrawn, not ignored, and a vulnerability, unmaintained or unsound."""
    if meta.get("withdrawn") or meta.get("id") in ignore:
        return False
    return meta.get("informational") in DENIED_CLASSES


def _affected_problems(adv: dict, meta: dict, graph: list[Key]) -> list[str]:
    kind = meta.get("informational") or "vulnerability"
    return [f"ADVISORIES: {n} {v} — {meta['id']} ({kind}): {meta.get('title', '')}"
            for n, v in graph if n == meta.get("package") and affected(adv, v)]


def _file_problems(path: Path, db: Path, graph: list[Key], ignore: set[str]) -> list[str]:
    adv = advisory(path.read_text(encoding="utf-8"))
    meta = adv.get("advisory", {})
    if not meta:
        return [f"ADVISORIES: {path.relative_to(db)} names a crate in the graph and "
                "holds no readable [advisory] block — an advisory not read is not cleared"]
    if not _is_denied(meta, ignore):
        return []
    return _affected_problems(adv, meta, graph)


def check_advisories(graph: list[Key], db: Path, ignore: set[str]) -> list[str]:
    problems: list[str] = []
    names = {n for n, _ in graph}
    for path in sorted((db / "crates").glob("*/*.md")):
        if path.parent.name in names:
            problems += _file_problems(path, db, graph, ignore)
    return problems
