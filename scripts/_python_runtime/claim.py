# SPDX-License-Identifier: Apache-2.0
"""The support claim (`requires-python`) against the interpreters the battery is pinned to."""

from __future__ import annotations

import _toolchains

from _python_runtime.config import CLAUSE, ECOSYSTEM

Bounds = tuple[tuple[int, int] | None, tuple[int, int] | None, bool]


def _bounds(specifier: str) -> tuple[Bounds | None, str | None]:
    """The (floor, ceiling, ceiling inclusive) of a specifier, or why it cannot be read."""
    floor: tuple[int, int] | None = None
    ceiling: tuple[int, int] | None = None
    ceiling_inclusive = False
    for raw in specifier.split(","):
        clause = raw.strip()
        match = CLAUSE.match(clause)
        if match is None:
            return None, f"cannot read the clause {clause!r} of requires-python {specifier!r}"
        operator, major, minor = match.group(1), int(match.group(2)), int(match.group(3))
        if operator == ">=":
            floor = (major, minor)
        elif operator in ("<", "<="):
            ceiling, ceiling_inclusive = (major, minor), operator == "<="
        else:
            return None, (
                f"the clause {clause!r} is not a bound this gate reads. Express the support "
                f"claim as `>=X.Y,<A.B`, so a reader and this gate agree on it"
            )
    return (floor, ceiling, ceiling_inclusive), None


def _bounded(specifier: str, bounds: Bounds) -> str | None:
    """Why the bounds do not state a closed range within one major version, if they do not."""
    floor, ceiling, _ = bounds
    if floor is None:
        return f"requires-python {specifier!r} states no lower bound"
    if ceiling is None:
        return (
            f"requires-python {specifier!r} has no upper bound, so it claims support for "
            f"every future Python minor — including ones no battery has ever run on"
        )
    if floor[0] != ceiling[0]:
        return f"requires-python {specifier!r} spans two major versions; not supported here"
    return None


def supported_minors(specifier: str) -> tuple[list[tuple[int, int]], str | None]:
    """The (major, minor) pairs a `requires-python` specifier admits, or why it cannot be read."""
    bounds, unreadable = _bounds(specifier)
    if bounds is None:
        return [], unreadable
    unbounded = _bounded(specifier, bounds)
    if unbounded is not None:
        return [], unbounded
    floor, ceiling, ceiling_inclusive = bounds
    last = ceiling[1] if ceiling_inclusive else ceiling[1] - 1
    return [(floor[0], minor) for minor in range(floor[1], last + 1)], None


def _coverage_refusal(specifier: str, claimed: list[tuple[int, int]], pinned: dict) -> str | None:
    """The claim and the pins must name the same minors: neither wider than the other."""
    missing = [f"{major}.{minor}" for major, minor in claimed if (major, minor) not in pinned]
    extra = [
        f"{major}.{minor} ({pinned[(major, minor)]})"
        for (major, minor) in sorted(pinned)
        if (major, minor) not in claimed
    ]
    if missing:
        return (
            f"requires-python {specifier} claims {', '.join(missing)}, which no pinned "
            f"interpreter measures. A support claim wider than its evidence reads one "
            f"runtime's green as proof about the rest"
        )
    if extra:
        return (
            f"[python].interpreters pins {', '.join(extra)}, outside the supported range "
            f"{specifier}. Either support it or stop measuring it"
        )
    return None


def check(specifier: str | None, entry) -> tuple[str | None, str]:
    """(refusal, summary) for one support claim measured against one runtime pin.

    Pure, and separate from `main` for one reason: `--selftest` has to be able to feed it
    the divergences this gate exists to catch. A gate whose logic can only be exercised by
    editing the real registry is a gate nobody proves is alive.
    """
    if not specifier:
        return "sdk/python/pyproject.toml declares no requires-python", ""
    claimed, unreadable = supported_minors(specifier)
    if unreadable is not None:
        return unreadable, ""

    pinned, malformed = _toolchains.interpreters(entry, ECOSYSTEM)
    if malformed is not None:
        return malformed, ""

    refusal = _coverage_refusal(specifier, claimed, pinned)
    if refusal is not None:
        return refusal, ""

    covered = ", ".join(pinned[key] for key in sorted(pinned))
    return None, (
        f"requires-python {specifier} claims {len(claimed)} minor(s), each measured on "
        f"exactly one pinned interpreter ({covered})"
    )
