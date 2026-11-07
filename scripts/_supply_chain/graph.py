# SPDX-License-Identifier: Apache-2.0
"""The crate graph: the lock's packages and edges, and the crates the Bazel build reaches."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

from _supply_chain.config import HUB, REPO

Key = tuple[str, str]


def lock_packages(lock_text: str) -> dict[Key, dict]:
    return {(p["name"], p["version"]): p for p in tomllib.loads(lock_text).get("package", [])}


def _dependency(dep: str, by_name: dict[str, list[str]]) -> Key:
    name, _, rest = dep.partition(" ")
    return name, rest.split(" ", 1)[0] if rest else by_name[name][0]


def resolve_edges(packages: dict[Key, dict]) -> dict[Key, list[Key]]:
    """Each package's dependencies as (name, version); a lock names the version only
    when the name alone is ambiguous."""
    by_name: dict[str, list[str]] = {}
    for name, version in packages:
        by_name.setdefault(name, []).append(version)
    return {key: [_dependency(dep, by_name) for dep in pkg.get("dependencies", [])]
            for key, pkg in packages.items()}


def repo_key(repo: str, packages: dict[Key, dict]) -> Key | None:
    """`<hub>__<name>-<version>` (build metadata's `+` spelled `-`) to its lock key."""
    for name, version in packages:
        if repo == f"{name}-{version.replace('+', '-')}":
            return name, version
    return None


def bazel(*args: str) -> str:
    proc = subprocess.run(["bazel", *args], cwd=REPO, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"supply-chain gate: `bazel {args[0]}` failed\n{proc.stderr[-2000:]}")
    return proc.stdout


def build_graph() -> dict[str, str]:
    """The hub crates the build graph reaches, as {canonical repo: '<name>-<version>'}."""
    labels = bazel("query", "--output=label", "deps(//...)").split()
    repos = {}
    for label in labels:
        repo = label.split("//", 1)[0]
        if HUB in repo:
            repos[repo] = repo.split(HUB, 1)[1]
    return repos


def _manifest_license(exec_root: str, file: str) -> tuple[str, str]:
    lines = (Path(exec_root) / file).read_text().splitlines()
    env = dict(line.split("=", 1) for line in lines if "=" in line)
    return f"{env['CARGO_PKG_NAME']}-{env['CARGO_PKG_VERSION']}", env.get("CARGO_PKG_LICENSE", "")


def crate_licenses(repos: dict[str, str]) -> dict[str, str]:
    targets = [f"{repo}//:cargo_toml_env_vars" for repo in sorted(repos)]
    bazel("build", *targets)
    exec_root = bazel("info", "execution_root").strip()
    files = bazel("cquery", "--output=files", "set(%s)" % " ".join(targets)).split()
    return dict(_manifest_license(exec_root, f) for f in files)
