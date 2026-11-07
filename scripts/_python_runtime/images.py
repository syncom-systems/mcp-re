# SPDX-License-Identifier: Apache-2.0
"""The third fact: a deploy image stage that installs the wheel runs a PINNED interpreter."""

from __future__ import annotations

from _python_runtime.config import FROM_LINE, INSTALLS_SDK, PYTHON_BASE


def wheel_stages(text: str) -> list[tuple[str, str | None]]:
    """`(base image, stage name)` for every stage in one Dockerfile that installs OUR wheel.

    A forward pass over the file rather than a regex over the whole text: the install
    command must be attributed to the stage it is IN, and the two `FROM` lines in
    `Dockerfile.loadgen` are two different interpreters. Attributing an install to the
    wrong stage would check the builder's Python and pass while the runtime's is wrong —
    which is the defect, inverted.
    """
    found: list[tuple[str, str | None]] = []
    base: str | None = None
    stage: str | None = None
    claimed = False
    for line in text.splitlines():
        opening = FROM_LINE.match(line.strip())
        if opening is not None:
            base, stage, claimed = opening.group(1), opening.group(2), False
            continue
        if base is None or claimed:
            continue
        if INSTALLS_SDK.search(line):
            found.append((base, stage))
            claimed = True
    return found


def _unreadable_base(where: str, base: str) -> str:
    return (
        f"{where} installs the MCP-RE wheel on base image {base!r}, which names "
        f"no Python version this gate can read. The interpreter that runs the "
        f"shipped wheel is part of the support claim and must be stated"
    )


def _unpinned_version(where: str, version: str, allowed: set[str]) -> str:
    inside = tuple(int(part) for part in version.split(".") if part.isdigit())
    hint = (
        "it is not an exact major.minor.patch, so what it resolves to is a "
        "property of the day it is built"
        if len(inside) != 3
        else "that interpreter is not one the battery is measured on"
    )
    return (
        f"{where} installs the MCP-RE wheel on python:{version}, and "
        f"[python].interpreters pins {', '.join(sorted(allowed))} — {hint}. "
        f"A deploy image outside the supported range cannot install the wheel "
        f"at all, and it fails at `docker build` inside a fleet proof rather "
        f"than where the support decision was taken"
    )


def _stage_refusal(where: str, base: str, allowed: set[str]) -> str | None:
    match = PYTHON_BASE.match(base)
    if match is None:
        return _unreadable_base(where, base)
    if match.group(1) in allowed:
        return None
    return _unpinned_version(where, match.group(1), allowed)


def check_images(dockerfiles: dict[str, str], pinned: dict[tuple[int, int], str]) -> str | None:
    """The third fact: a stage that installs the wheel runs a PINNED interpreter.

    `dockerfiles` is `{path: text}` so `--selftest` can feed it files that do not exist;
    a gate whose only input is the real tree is one nobody proves is alive.
    """
    allowed = set(pinned.values())
    for path in sorted(dockerfiles):
        for base, stage in wheel_stages(dockerfiles[path]):
            where = f"{path} stage {stage!r}" if stage else path
            refusal = _stage_refusal(where, base, allowed)
            if refusal is not None:
                return refusal
    return None
