# SPDX-License-Identifier: Apache-2.0
"""Negative controls: prove the nesting and size lints are enabled and fire on the right side of their thresholds."""

from __future__ import annotations

from _clippy_ratchet.config import STRICT_CONF
from _clippy_ratchet.measure import clippy_code, clippy_diagnostics, primary_spans

_DEFAULT_NESTING_THRESHOLD = 3
#: `depth_two` spans lines 5-12 of probes/nest.rs, `depth_three` lines 14-23.
_DEPTH_TWO_LINES = range(5, 13)
_DEPTH_THREE_LINES = range(14, 24)


def _nesting_threshold() -> int:
    lines = (STRICT_CONF / ".clippy.toml").read_text().splitlines()
    values = [int(line.split("=")[1].strip()) for line in lines
              if line.strip().startswith("excessive-nesting-threshold")]
    return values[-1] if values else _DEFAULT_NESTING_THRESHOLD


def _nesting_flagged_lines(diagnostics: list[dict]) -> set[int]:
    return {span["line_start"] for message in diagnostics
            if clippy_code(message) == "clippy::excessive_nesting"
            for span in primary_spans(message)}


def _nesting_failure(threshold: int, two_flagged: bool, three_flagged: bool) -> str | None:
    if two_flagged:
        return (
            f"nesting probe: FAIL — depth 2 was rejected at "
            f"excessive-nesting-threshold = {threshold}. The rule is 'deeper than 2', "
            f"so depth 2 must be accepted."
        )
    if not three_flagged:
        return (
            f"nesting probe: FAIL — depth 3 was NOT rejected at "
            f"excessive-nesting-threshold = {threshold}. The lint is configured but "
            f"enforces nothing; this is the inert-configuration failure ADR-MCPRE-061 "
            f"§6.1 exists to prevent."
        )
    return None


def nesting_probe() -> int:
    """Negative control for the nesting rule: depth <= 2 accepted, depth > 2 rejected.

    Required by the C-5 ruling. A configured lint is not an enforced rule until something
    demonstrates it fires on the far side of the boundary and stays silent on the near
    side. Without this, `excessive-nesting-threshold` could be off by one — and it is
    off-by-one-shaped: the threshold names the depth that is REJECTED, so "deeper than
    two levels" is threshold 3, not 2.
    """
    threshold = _nesting_threshold()
    rc, stderr, diagnostics = clippy_diagnostics(["//config/clippy-strict:nest_probe"])
    if rc != 0 or not diagnostics:
        print(f"nesting probe: FAIL — the probe did not build under the gate's flags, so it "
              f"measured nothing (exit {rc}).\n{stderr[-1500:]}")
        return 1
    flagged = _nesting_flagged_lines(diagnostics)
    failure = _nesting_failure(
        threshold,
        any(ln in _DEPTH_TWO_LINES for ln in flagged),
        any(ln in _DEPTH_THREE_LINES for ln in flagged),
    )
    if failure:
        print(failure)
        return 1
    print(
        f"nesting probe: PASS — at excessive-nesting-threshold = {threshold}, "
        f"depth 2 accepted and depth 3 rejected (ADR-MCPRE-061 §6.5, C-5)."
    )
    return 0


def _fired_lints(diagnostics: list[dict]) -> set[str]:
    codes = (clippy_code(message) for message in diagnostics)
    return {code.split("::", 1)[1] for code in codes if code.startswith("clippy::")}


def _arithmetic_hits(diagnostics: list[dict]) -> int:
    return sum(
        1 for message in diagnostics
        if clippy_code(message) == "clippy::arithmetic_side_effects" and primary_spans(message)
    )


def _activation_failure(fired: set[str], arithmetic_hits: int) -> str | None:
    missing = [x for x in ("too_many_lines", "excessive_nesting", "arithmetic_side_effects")
               if x not in fired]
    if missing:
        return (
            "activation probe: FAIL — a file violating the size, nesting and arithmetic "
            f"rules did not trigger {missing}. `.clippy.toml` sets thresholds but does "
            "not switch on allow-by-default lints. These lints are enabled by this "
            "gate's ADOPTED list, which becomes the `-W` flags in LINT_FLAGS — NOT by "
            "`[workspace.lints.clippy]`, which ADR-MCPRE-061 §6.2 rejects because every "
            "clippy lane here runs `--all-targets -- -D warnings` and a workspace entry "
            "would turn the exempt test-code sites into hard errors. Check ADOPTED, and "
            "check the thresholds in config/clippy-strict/.clippy.toml."
        )
    # The exclusions matter as much as the hits: if the lint ever started reporting
    # saturating, wrapping, `Wrapping`, float or const arithmetic, the 124-site baseline
    # would stop meaning what ADR-MCPRE-061 §6.6 says it means.
    if arithmetic_hits != 1:
        return (
            f"activation probe: FAIL — clippy::arithmetic_side_effects fired on "
            f"{arithmetic_hits} of 6 arithmetic expressions; exactly one (the unconstrained "
            f"`x + 1`) should fire. Saturating, wrapping, `Wrapping`, float and const "
            f"arithmetic are excluded by the lint's definition, and ADR-MCPRE-061 §6.6 "
            f"relies on those exclusions for what a hit MEANS."
        )
    return None


def activation_probe() -> int:
    """Negative control for §6.1: prove the size/nesting lints are actually ENABLED.

    `.clippy.toml` sets thresholds; it does not switch on allow-by-default lints. Before
    this probe existed the project claimed a mechanically enforced 60-line function rule on
    the strength of `too-many-lines-threshold = 60` plus a `-D warnings` lint lane,
    and an 80-line function produced no warning at all.

    The probe compiles a file that violates the size and nesting rules under the EXACT flag
    list `measure()` uses, so it cannot drift from the gate it vouches for.
    """
    rc, stderr, diagnostics = clippy_diagnostics(["//config/clippy-strict:activation_probe"])
    if rc != 0 or not diagnostics:
        print(f"activation probe: FAIL — the probe did not build under the gate's flags, so "
              f"it measured nothing (exit {rc}).\n{stderr[-1500:]}")
        return 1
    failure = _activation_failure(_fired_lints(diagnostics), _arithmetic_hits(diagnostics))
    if failure:
        print(failure)
        return 1
    print(
        "activation probe: PASS — a 70-line function, a depth-3 block and an "
        "unconstrained `x + 1` fired; saturating, wrapping, `Wrapping`, float and const "
        "arithmetic did not (ADR-MCPRE-061 §6.1, §6.6)."
    )
    return 0
