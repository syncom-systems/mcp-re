# SPDX-License-Identifier: Apache-2.0
"""What a runtime pin must look like: the shape check, and the malformed pins both gates refuse."""

from __future__ import annotations

#: Per ecosystem: what one pinned runtime is called, what a support line is called, and how
#: many leading version components name that line. CPython's support lines are minors;
#: Node's are majors.
ECOSYSTEMS = {
    "python": ("interpreter", "minor", 2),
    "typescript": ("runtime", "major", 1),
}


def _entry_problem(entry: object, ecosystem: str) -> str | None:
    """Why the lock's `[<ecosystem>]` table cannot back a runtime claim, or None."""
    noun, _, _ = ECOSYSTEMS[ecosystem]
    if not isinstance(entry, dict):
        return f"toolchains.lock.toml has no [{ecosystem}] runtime pin"
    if entry.get("state") != "resolved":
        return f"[{ecosystem}] is unresolved, so no {noun} identity backs the claim"
    versions = entry.get("interpreters")
    if not isinstance(versions, list) or not versions:
        return f"[{ecosystem}].interpreters names no {noun}"
    return None


def _is_exact_version(version: object) -> bool:
    parts = str(version).split(".")
    return len(parts) == 3 and all(part.isascii() and part.isdigit() for part in parts)


def interpreters(entry, ecosystem: str) -> tuple[dict[tuple[int, ...], str], str | None]:
    """`({support line: exact version}, None)` for a well-formed runtime pin, else `({}, why)`.

    `entry` is the lock's `[<ecosystem>]` table, or None when the lock has none. The key of
    each pinned version is its support line: `(3, 14)` for CPython 3.14.7, `(22,)` for Node
    22.23.2.
    """
    problem = _entry_problem(entry, ecosystem)
    if problem is not None:
        return {}, problem
    noun, line, width = ECOSYSTEMS[ecosystem]
    pinned: dict[tuple[int, ...], str] = {}
    for version in entry["interpreters"]:
        if not _is_exact_version(version):
            return {}, (
                f"[{ecosystem}].interpreters entry {version!r} is not an exact "
                f"major.minor.patch version. A {line} alone lets two different builds record "
                f"one identity"
            )
        key = tuple(int(part) for part in str(version).split(".")[:width])
        if key in pinned:
            label = ".".join(str(part) for part in key)
            return {}, (
                f"[{ecosystem}].interpreters names {line} {label} twice ({pinned[key]}, "
                f"{version}); one {line} is measured on one {noun}"
            )
        pinned[key] = str(version)
    return pinned, None


def pin_shape_cases(ecosystem: str, good: list[str]) -> list[tuple[str, dict | None, bool]]:
    """`(name, entry, must_refuse)`: the malformed pins both runtime gates must refuse.

    `good` is an exact pin set the calling gate's own claim accepts, with at least one
    entry; every case is a one-step corruption of it, plus `good` itself, which must pass.
    Both gates run these through their own `check`, so a pin-shape refusal one of them
    stopped making is caught by the fixture they share rather than by remembering to copy
    a case.
    """
    _, line, _ = ECOSYSTEMS[ecosystem]
    last = good[-1].split(".")
    truncated = ".".join(last[:2])
    same_line = ".".join([*last[:2], str(int(last[2]) + 1)])
    return [
        ("no runtime pin at all", None, True),
        ("an unresolved runtime pin", {"state": "unresolved"}, True),
        ("a resolved pin naming nothing", {"state": "resolved", "interpreters": []}, True),
        (
            f"a {line} pinned without a patch version",
            {"state": "resolved", "interpreters": [*good[:-1], truncated]},
            True,
        ),
        (
            f"a {line} whose patch is a non-ASCII digit",
            {"state": "resolved", "interpreters": [*good[:-1], ".".join([*last[:2], "\u00b2"])]},
            True,
        ),
        (
            f"one {line} pinned twice",
            {"state": "resolved", "interpreters": [*good, same_line]},
            True,
        ),
        ("the claim and the pin agreeing exactly", {"state": "resolved", "interpreters": list(good)}, False),
    ]
