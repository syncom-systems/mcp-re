# SPDX-License-Identifier: Apache-2.0
"""Yanked versions, from the crates.io sparse index (the one check that needs the network)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from _supply_chain.config import INDEX
from _supply_chain.graph import Key


def index_path(name: str) -> str:
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def yanked_versions(name: str) -> set[str]:
    with urllib.request.urlopen(f"{INDEX}/{index_path(name)}", timeout=30) as resp:
        entries = [json.loads(line) for line in resp.read().decode().splitlines() if line.strip()]
    return {e["vers"] for e in entries if e.get("yanked")}


def check_yanked(graph: list[Key]) -> list[str]:
    names = sorted({n for n, _ in graph})
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            yanked = dict(zip(names, pool.map(yanked_versions, names)))
    except urllib.error.URLError as err:
        raise SystemExit(f"supply-chain gate: the crates.io index is unreachable ({err}); "
                         "a yanked check that could not run is not a pass")
    return [f"ADVISORIES: {n} {v} is yanked on crates.io" for n, v in graph if v in yanked[n]]
