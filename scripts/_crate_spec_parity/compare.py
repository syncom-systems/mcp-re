# SPDX-License-Identifier: Apache-2.0
"""The three comparisons: specs against requests, locks against locks, repin inputs."""

from __future__ import annotations

import json

from _crate_spec_parity.config import (
    BAZEL_ONLY_SPECS,
    CRATE_EXTENSION,
    REPIN_INPUTS,
    SPLICE_ROOT,
    UNSET,
)
from _crate_spec_parity.specs import Spec, bazel_only_packages, declared, locked, requested


def _spec_diffs(name: str, want: Spec, have: Spec) -> list[str]:
    (wv, wf, wd), (hv, hf, hd) = want, have
    problems = []
    if wv != hv:
        problems.append(f"SPECS: `{name}` version: workspace {wv}, spec {hv}")
    if wf != hf:
        problems.append(
            f"SPECS: `{name}` features: workspace only {sorted(wf - hf)}, "
            f"spec only {sorted(hf - wf)}"
        )
    if wd != hd:
        problems.append(f"SPECS: `{name}` default features: workspace {wd}, spec {hd}")
    return problems


def spec_problems(want: dict[str, Spec], have: dict[str, Spec]) -> list[str]:
    problems = [
        f"SPECS: the workspace requests `{name}` and MODULE.bazel declares no spec for it"
        for name in sorted(set(want) - set(have))
    ]
    problems += [
        f"SPECS: MODULE.bazel declares `{name}` and no workspace member requests it"
        for name in sorted(set(have) - set(want) - set(BAZEL_ONLY_SPECS))
    ]
    for name in sorted(set(want) & set(have)):
        problems += _spec_diffs(name, want[name], have[name])
    return problems


def _lock_problem(
    name: str, version: str, checksum: str | None, in_cargo: dict[tuple[str, str], str | None]
) -> str | None:
    if (name, version) not in in_cargo:
        others = sorted(v for n, v in in_cargo if n == name)
        return f"LOCKS: bazel/crates.lock has {name} {version}; Cargo.lock has {others or 'none'}"
    if in_cargo[(name, version)] != checksum:
        return f"LOCKS: {name} {version} has a different checksum in the two locks"
    return None


def lock_problems(bazel_lock: str, cargo_lock: str) -> tuple[list[str], int]:
    """The lock disagreements and how many packages were compared."""
    in_bazel, in_cargo = locked(bazel_lock), locked(cargo_lock)
    exempt = bazel_only_packages(bazel_lock)
    compared = [
        (name, version, checksum)
        for (name, version), checksum in sorted(in_bazel.items())
        if name != SPLICE_ROOT and name not in exempt
    ]
    found = (_lock_problem(*entry, in_cargo) for entry in compared)
    return [p for p in found if p], len(compared)


def compare(
    meta: dict, module_text: str, bazel_lock: str, cargo_lock: str
) -> tuple[list[str], int, int]:
    have = declared(module_text)
    problems = spec_problems(requested(meta), have)
    locks, compared = lock_problems(bazel_lock, cargo_lock)
    problems += locks
    if not have:
        problems.append(
            "SPECS: no crate.spec was read from MODULE.bazel — comparing nothing is not a pass"
        )
    if not compared:
        problems.append(
            "LOCKS: no package was read from bazel/crates.lock — comparing nothing is not a pass"
        )
    return problems, len(have), compared


def _recorded_env(module_lock: str) -> dict[str, str] | None:
    """The extension's recorded `ENV:` inputs, or None when the lock records none."""
    try:
        recorded = json.loads(module_lock)["moduleExtensions"][CRATE_EXTENSION]["general"][
            "recordedInputs"
        ]
    except (KeyError, TypeError, ValueError):
        return None
    return {r[4:].rsplit(" ", 1)[0]: r.rsplit(" ", 1)[1] for r in recorded if r.startswith("ENV:")}


def repin_inputs(module_lock: str) -> list[str]:
    """Problems with the repin-only environment inputs MODULE.bazel.lock records.

    `CARGO_BAZEL_REPIN=1 bazel mod show_extension ...` writes `ENV:CARGO_BAZEL_REPIN 1` into the
    extension's recorded inputs. CI runs with the variable unset, so Bazel re-evaluates the
    extension and rewrites the tracked lockfile mid-job, and every fingerprint taken afterwards
    describes a tree that is not the commit. A build does not notice the rewrite, so only this
    check does. Repin, then run one plain invocation so the lock records the inputs unset."""
    values = _recorded_env(module_lock)
    if values is None:
        return [
            f"REPIN: MODULE.bazel.lock records no inputs for {CRATE_EXTENSION} — "
            "comparing nothing is not a pass"
        ]
    problems = []
    for name in REPIN_INPUTS:
        if name not in values:
            problems.append(f"REPIN: MODULE.bazel.lock does not record ENV:{name}")
        elif values[name] != UNSET:
            problems.append(
                f"REPIN: MODULE.bazel.lock records ENV:{name} = {values[name]!r}; "
                "a plain build would rewrite it (run one plain bazel invocation "
                "after the repin)"
            )
    return problems
