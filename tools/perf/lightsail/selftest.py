# SPDX-License-Identifier: Apache-2.0
"""Local selftest of the Lightsail orchestration — no host, no Redis, no cloud.

Two layers. Unit cases pin the decisions: the knee and plateau rules, every attribution
rule (each with the telemetry that must fire it), rep validation, the rig verdict mapping,
the ceiling statement in all three outcomes, and the host identity check. The campaign case
then runs the REAL `ceiling.py campaign` end to end against fake instruments (small Python
programs standing in for the bench and the rig) and checks the run directory: the layout,
a deliberately failing rep recorded as INCOMPLETE without stopping the campaign, the
offered-load ladder climbing on a CLIENT verdict, a rung whose probe step hit errors recorded
as INVALID and kept out of every number, a host that is not the declared context stopping
before any measurement, and a summary that states its rule set. A tiny RESP server stands in
for the replay tier's primary, so the store-side accounting a rung is checked against is real.

The unit cases are in `selftest_units`, the campaign case in `selftest_campaign`, and the fake
instruments both use in `selftest_fakes`.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from selftest_campaign import campaign_case
from selftest_units import run_units


def telemetry_case() -> None:
    """On Linux, the /proc sampler must produce attributable samples around real work."""
    if not os.path.isdir("/proc/self"):
        return
    from telemetry import Telemetry, parse_pid_stat, parse_sockstat
    assert parse_pid_stat("1 (a b) S 0 0 0 0 0 0 0 0 7 0 50 25 0 0 0 0 4 0 0 0 300 0")["ticks"] == 75
    assert parse_sockstat("TCP: inuse 5 orphan 0 tw 12 alloc 9 mem 1\n")["tw"] == 12
    from telemetry import parse_netstat
    assert parse_netstat("TcpExt: A ListenOverflows ListenDrops\nTcpExt: 1 7 9\n") == {"ListenOverflows": 7, "ListenDrops": 9}
    with tempfile.TemporaryDirectory() as tmp:
        tel = Telemetry(Path(tmp), os.cpu_count() or 1, require=False)
        # The work runs in a CHILD, as every measured instrument does: CPU burned on this
        # interpreter's own thread starves the sampler of the GIL, and on a host with a busy
        # /proc not one sample completes inside the window.
        with tel:
            subprocess.run([sys.executable, "-c",
                            "import time\nend = time.time() + 2.5\nwhile time.time() < end: sum(i * i for i in range(10000))"],
                           check=True)
        summary = tel.result
        assert summary["available"] and summary["samples"] >= 1, summary
        assert summary["host_busy_avg"] > 0 and "other" in summary["categories"], summary
        assert (Path(tmp) / "telemetry" / "proc-samples.jsonl").stat().st_size > 0


def run_all() -> int:
    run_units()
    telemetry_case()
    campaign_case()
    print("lightsail ceiling selftest: OK (rules, attribution, identity stop, ladder, failure recording, layout, "
          "replay pool launch and refusal, invalid rungs, signer budget cap, stage timers, replication gaps, "
          "isolation plan)")
    return 0
