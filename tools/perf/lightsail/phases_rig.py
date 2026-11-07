# SPDX-License-Identifier: Apache-2.0
"""What a saturation-rig rung is allowed to claim: its request budget, its steps, its verdict."""

from __future__ import annotations

import re

from phases_context import RUNG_REQUEST_CEILING


def rung_requests(conns: int, requests_per_connection: float, gen_cap: int) -> tuple[int, bool]:
    """(requests per generator, whether the signer budget capped it) for one rung: the rig may
    run every step from 2 to `gen_cap` generators, so the worst case sends the sum of them."""
    wanted = int(conns * requests_per_connection)
    ceiling = RUNG_REQUEST_CEILING // sum(range(2, gen_cap + 1))
    return min(wanted, ceiling), wanted > ceiling


def _probe_was_dropped(gain: float | None) -> bool:
    """The M+1 probe bought nothing, so the rig kept row M and did not fold the probe in."""
    return gain is not None and gain <= 0


def rig_steps(row: dict, gen_cap: int) -> list[int]:
    """The generator count of every step `saturation_rig` ran for `row`. It starts at 2 and
    adds one generator per step; a probe at M+1 that did not beat M (gain <= 0) is not folded
    into the row, so it ran IN ADDITION to the steps up to M."""
    gens = row["generators"]
    steps = list(range(2, gens + 1))
    if _probe_was_dropped(row.get("last_gain_pct")) and gens < gen_cap:
        steps.append(gens + 1)
    return steps


def rig_verdict(row: dict, log_text: str, store_sets: int | None, expected_sets: int) -> tuple[str, list[str]]:
    """PROXY / CLIENT from the rig's criterion, or INVALID with every reason that applies."""
    reasons = []
    if row.get("failures", 0) or row.get("failure_pct", 0.0) > 0:
        reasons.append(f"the row counts {row.get('failures')} failure(s)")
    errors = [line.strip() for line in log_text.splitlines() if "generator error:" in line]
    if errors:
        codes = sorted(set(re.findall(r'"wire_code":"([a-z0-9_.-]+)"', "\n".join(errors))))
        reasons.append(f"{len(errors)} generator error(s) in the rung" + (f" ({', '.join(codes)})" if codes else ""))
    if store_sets is None:
        reasons.append("the replay store's SET count over the rung could not be read")
    elif store_sets != expected_sets:
        reasons.append(f"the replay store saw {store_sets} SETs; the rig's steps sent {expected_sets}")
    if reasons:
        return "INVALID", reasons
    return ("PROXY" if row.get("saturated") else "CLIENT"), []
