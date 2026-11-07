"""Teardown, and the verification that makes it part of the verdict."""

from __future__ import annotations

import time

from run_supervisor_resources import GRACE_S, VERIFY_S, docker, owned_resources


def teardown(run: str) -> dict:
    """Remove everything this run created. Unconditional: called on every exit path."""
    mine = owned_resources(run)
    for cid in mine["containers"]:
        docker("stop", "-t", str(int(GRACE_S)), cid)
        docker("rm", "-fv", cid)
    for net in mine["networks"]:
        docker("network", "rm", net)
    for vol in mine["volumes"]:
        docker("volume", "rm", "-f", vol)
    return {"attempted": mine}


def assert_clean_end(run: str) -> dict:
    """Verify by re-reading the daemon. A teardown that ran is not a teardown that worked."""
    deadline = time.monotonic() + VERIFY_S
    remaining = owned_resources(run)
    while remaining["total"] and time.monotonic() < deadline:
        time.sleep(1)
        remaining = owned_resources(run)
    return {"clean": remaining["total"] == 0, "remaining": remaining}
