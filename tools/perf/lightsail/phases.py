# SPDX-License-Identifier: Apache-2.0
"""Phase A (canonical cold-mTLS harness) and Phase B (saturation rig) runners.

Both instruments are the released v0.18.0 binaries, run as plain processes with absolute
paths. Nothing here changes what they measure: the envelope, the replay tier string, the
saturation criterion are theirs. What this module adds is the sweep, the telemetry window
around each measurement, and a record per measurement that says whether it is valid.

PHASE B AND THE RESOLUTION OF THE M -> M+1 TEST. The rig calls a row PROXY when one more
generator raises throughput by <= 5%. Adding one generator to M raises offered load by at
most 1/M, so for M >= 20 a row that is entirely client-limited still cannot gain more than
5%: the test loses the ability to say CLIENT and every row reads PROXY. The criterion is
therefore kept exactly (5%), and offered load is raised the other way: the generator count
stays <= GEN_CAP (one step >= 8.3%) and the connections per generator climb a ladder, with
requests scaled to keep the per-connection request count constant. A point still CLIENT at
the top rung is a floor, and `analysis.py` decides whether the host could have said more.

A RUNG IS EVIDENCE ONLY IF EVERY STEP OF IT WAS SERVED. The rig climbs M -> M+1 inside one
proxy process and keeps the better of the two rows; a probe step whose generators hit errors
comes out SLOWER, and the rig then reads its collapse as "one more generator bought nothing"
and stamps the row PROXY. So a rung is INVALID — never PROXY, never CLIENT — when the rig log
carries any `generator error:`, when its row counts any failure, or when the replay store's
own SET count over the rung — read from the primary immediately before and after it — differs from what the
rig's steps sent (`rig_steps`). The last check is independent of the rig: a generator that died without reporting cannot hide from it.

THE SIGNER RETENTION BUDGET. Every rig generator signs as the same actor, and one proxy
process admits at most `SIGNER_RETENTION_BUDGET` fresh nonces from one actor while they are
retained (the security bound in `mcp-re-proxy/src/async_replay/bounds.rs`, kept as is). The
requests per generator are therefore capped so that a rung climbing all the way to
`gen_cap` stays below it; the cap and whether it applied are recorded per rung.

The parts live beside this file: `phases_context` (constants, instruments, run context, replay
tier health), `phases_rig` (rung budget, steps and verdict), `phases_launch` (the proxy
launcher and its startup transcript), `phases_a` and `phases_b` (the two phases).
"""

from __future__ import annotations

from phases_a import Topology, phase_a_point, validate_bench_rep
from phases_b import BPoint, phase_b_point
from phases_context import (
    DEFAULT_REPLAY_POOL,
    GEN_CAP,
    LADDER,
    PASS_LINE,
    REQUESTS_PER_CONNECTION,
    RUNG_REQUEST_CEILING,
    SIGNER_RETENTION_BUDGET,
    STARTUP_LOG_ENV,
    Binaries,
    Context,
)
from phases_launch import proxy_launcher, startup_facts
from phases_rig import rig_steps, rig_verdict, rung_requests

__all__ = [
    "BPoint", "Binaries", "Context", "DEFAULT_REPLAY_POOL", "GEN_CAP", "LADDER", "PASS_LINE",
    "REQUESTS_PER_CONNECTION", "RUNG_REQUEST_CEILING", "SIGNER_RETENTION_BUDGET",
    "STARTUP_LOG_ENV", "Topology", "phase_a_point", "phase_b_point", "proxy_launcher",
    "rig_steps", "rig_verdict", "rung_requests", "startup_facts", "validate_bench_rep",
]
