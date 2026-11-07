"""The diagnostic and operator commands: `status`, `dump-env`, `recover`, `job-completed`."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict

import host_gate
import host_gate_config
import host_locks
import vm_participant
from job_identity import JobIdentity
from runner_arbiter_common import (
    EXIT_OK,
    EXIT_REFUSED,
    inhibition_file,
    release_inhibition,
    vm_readers,
)


def cmd_job_completed(paths, ident: JobIdentity) -> int:
    result = host_gate.job_completed(paths, ident)
    if result["released_reservation"] and inhibition_file(paths).exists():
        # Only release what we applied. A VM left stopped is a visible, safe
        # condition; a VM left running during a measurement would not be.
        release_inhibition(paths)
    return EXIT_OK


def cmd_status(paths) -> int:
    host_gate.repair_stale_gate(paths)
    reachable = vm_participant.available()
    print(json.dumps({
        "root": str(paths["root"]), "mirror": str(paths["mirror"]),
        "gate": host_gate.read_gate(paths),
        "active": host_gate.active_records(paths),
        "heavy_runners": sorted(host_gate_config.HEAVY_RUNNERS),
        "locks": host_locks.lock_state(paths["root"]),
        "holders": host_locks.holders(paths["root"]),
        "macos_runner_workers": host_gate.macos_workers(),
        "vm_unit_active": vm_participant.unit_active() if reachable else "unreachable",
        "vm_runner_workers": vm_participant.worker_count() if reachable else "unreachable",
        "participation": host_gate.verify_participation(vm_readers()),
        "loadavg": os.getloadavg(), "ncpu": os.cpu_count(),
    }, indent=2, default=str))
    return EXIT_OK


def cmd_dump_env(ident: JobIdentity) -> int:
    keys = sorted(k for k in os.environ if k.startswith(("GITHUB_", "RUNNER_", "ACTIONS_")))
    print(json.dumps({"env": {k: os.environ[k] for k in keys},
                      "derived": asdict(ident), "is_slo": ident.is_slo}, indent=2))
    return EXIT_OK


def cmd_recover(paths, args) -> int:
    if not args.i_verified_no_owner_job_is_running:
        print("refusing: a stale reservation is an operator condition, not a timer's to "
              "clear. Confirm no owner job is live, then pass "
              "--i-verified-no-owner-job-is-running.", file=sys.stderr)
        return EXIT_REFUSED
    live = host_gate.macos_workers()
    if live:
        print(f"refusing: {len(live)} Runner.Worker process(es) still running ({live}). "
              "Clearing now would fail open.", file=sys.stderr)
        return EXIT_REFUSED
    if vm_participant.available() and vm_participant.worker_count() > 0:
        print("refusing: the VM still has a live Runner.Worker.", file=sys.stderr)
        return EXIT_REFUSED
    if args.clear_reservation:
        with host_gate.mutex(paths):
            host_gate.commit(paths, {"schema": host_gate.SCHEMA, "state": host_gate.OPEN,
                                     "recovered_at": host_gate.now()})
        if inhibition_file(paths).exists():
            release_inhibition(paths)
        host_gate.log(paths, "recover.reservation_cleared")
    return EXIT_OK
