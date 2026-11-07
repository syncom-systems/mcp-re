# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict on the real machines."""

from __future__ import annotations

import sys
from pathlib import Path

from _lifecycle_purity.config import ALLOWED_STD_PATHS, REPO_ROOT, TARGETS
from _lifecycle_purity.dependencies import child_modules, external_dependencies, production_half


def _child_file(target: Path, name: str) -> Path:
    child = target.with_suffix("") / f"{name}.rs"
    if not child.exists():
        child = target.with_suffix("") / name / "mod.rs"
    return child


def _findings(target: Path) -> list[str]:
    """The machine's own external dependencies, and those of each child module it declares."""
    text = target.read_text(encoding="utf-8")
    found = external_dependencies(text)
    for name in child_modules(production_half(text)):
        child = _child_file(target, name)
        if not child.exists():
            found.append(f"0: child module `{name}` has no file this gate can check")
            continue
        found.extend(
            f"{child.relative_to(REPO_ROOT)}:{entry}"
            for entry in external_dependencies(child.read_text(encoding="utf-8"), child=True)
        )
    return found


def _holds(target: Path) -> bool:
    rel = target.relative_to(REPO_ROOT)
    if not target.exists():
        print(
            f"FAIL: {rel} is missing. If the machine moved, move this gate with it — "
            f"a gate whose target vanished silently stops proving anything.",
            file=sys.stderr,
        )
        return False
    found = _findings(target)
    if found:
        print(f"FAIL: {rel} has acquired external dependencies:", file=sys.stderr)
        for entry in found:
            print(f"  {entry}", file=sys.stderr)
        return False
    print(f"lifecycle_purity_gate: PASS — {rel} depends on no production module")
    return True


def judge() -> int:
    results = [_holds(target) for target in TARGETS]
    if not all(results):
        print(
            "\nA state machine here is a value: it depends on no production module, so it "
            "cannot\nacquire behaviour. If one genuinely needs a dependency, that is an "
            "architecture\nchange — see verification/baseline/phase2-pilot-boundary-decision.md.",
            file=sys.stderr,
        )
        return 1
    allowed = ", ".join(sorted(ALLOWED_STD_PATHS))
    print(f"lifecycle_purity_gate: PASS — {len(TARGETS)} machines (allowed std: {allowed})")
    return 0
