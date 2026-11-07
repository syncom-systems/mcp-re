"""The physical-host admission gate shared by every runner application on dev1.

WHY
===

`slo.yml` asserted that "a self-hosted runner APPLICATION executes one job at a time, so no
other Actions job runs here". Measured false on 2026-09-10. dev1 hosts THREE registered
runner applications which do not compete for jobs -- they compete for the machine:

    dev1         /Users/mats/dev/actions-runner         -> github.com/matssun/code    (macOS)
    dev1-mcp-re  /Users/mats/dev/actions-runner-mcp-re  -> github.com/matssun/mcp-re  (macOS)
    dev1-linux   /home/mats.guest/actions-runner        -> github.com/matssun/code    (colima VM)

Serving different repositories, GitHub schedules all three concurrently. The failed rep ran
at host load 12.43 beside another runner.

THE INVARIANT
=============

    Once a host reservation is granted, no runner on this physical host may admit a NEW
    non-owner job until the reservation is released.

Admission is decided in a pre-job hook, the only place a job can still be refused: it runs
synchronously after GitHub assigns the job and before any step executes. A workflow cannot
refuse work already handed to a runner, which is why this does not live in YAML.

RESERVE FIRST, THEN DRAIN
=========================

The reservation is granted BEFORE the owner looks at who else is active. The reverse order
admits the exact failure being removed, because the queue refills in the gap:

    check quiet -> another runner accepts work -> SLO starts          WRONG

With reserve-first, work already executing drains while NO replacement work is admitted
anywhere on the host.

    OPEN --grant--> RESERVING(owner) --drained+quiescent--> RESERVED(owner) --> RELEASED --> OPEN

The reservation is an OWNED record, never a boolean: a bare "SLO running" flag cannot say
who holds it, cannot tell the owner's own job from a stranger's, and leaves an operator
facing a stuck host with nothing to act on.

TWO KERNELS, ONE AUTHORITY
==========================

`fcntl` is authoritative for admission and for state TRANSITIONS, and only on macOS. It is deliberately NOT
stretched across the virtiofs boundary into the VM, where advisory locking is not
dependable -- a lock that silently fails to lock is worse than no lock, because the code
reads as though it were safe.

The VM is therefore an ADMISSION PARTICIPANT, not a lock participant. macOS commits a
decision; the VM reads that committed decision and gates its own execution:

    /opt/verification/runner-arbiter/gate.json   authoritative, macOS only, fcntl-guarded
    ~/.runner-arbiter/gate.json                  committed mirror, atomic-renamed, readable
                                                 from BOTH kernels

Publication is `os.replace`, so a VM reader sees either the previous committed state or the
new one, never a partial write. That is precisely why the reader needs no lock: it does not
participate in the transition, it obeys the outcome.

FAIL-CLOSED, INCLUDING THE PARTICIPATION QUESTION
=================================================

A runner that cannot read the gate must not admit work. And the owner must not MEASURE
unless every registered runner application is known to participate: an unhooked runner is
not a quiet runner, it is an unobserved one. Where participation cannot be confirmed,
stopping that listener remains an acceptable FALLBACK (see `vm_participant`), but it is no
longer the normal mechanism.

ADMISSION IS KERNEL LOCKS, HELD FOR THE JOB'S LIFETIME
=====================================================

Since 2026-09-26 admission on macOS is decided by `flock` locks that a per-job holder keeps
until the job's Runner.Worker exits (`host_locks`, `lock_holder`). The kernel releases them
the instant the holder ends -- job finished, cancelled, killed, runner stopped, host
rebooted -- so no lock can outlive its job, and nothing has to clean up. The files in this
directory (gate.json, holders/) describe the locks for the VM and for operators; where a file
and a lock disagree, the lock is right and the file is repaired. No TTL releases anything.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from host_gate_admission import Lease, Watch, admit_job, admit_local, local_lease_key, lock_bounds  # noqa: E402
from host_gate_capacity import free_gb, is_recovery, refuse_if_disk_exhausted, work_volume  # noqa: E402
from host_gate_config import (  # noqa: E402
    MIRROR, OPEN, RELEASED, RESERVED, RESERVING, ROOT, SCHEMA,
)
from host_gate_participation import (  # noqa: E402
    VmProbes, hook_from_env_text, listener_started_after_env, macos_workers, runner_is_stopped,
    verify_participation,
)
from host_gate_quiescence import await_quiescence  # noqa: E402
from host_gate_reservation import (  # noqa: E402
    activate, await_drain, grant_reservation, job_completed, release_owner, repair_stale_gate,
)
from host_gate_state import (  # noqa: E402
    active_records, commit, ensure_layout, log, mutex, now, paths, read_gate, write_atomic,
)

__all__ = [
    "Lease", "MIRROR", "OPEN", "RELEASED", "RESERVED", "RESERVING", "ROOT", "SCHEMA", "VmProbes",
    "Watch", "activate", "active_records", "admit_job", "admit_local", "await_drain",
    "await_quiescence", "commit", "ensure_layout", "free_gb", "grant_reservation",
    "hook_from_env_text", "is_recovery", "job_completed", "listener_started_after_env",
    "local_lease_key", "lock_bounds", "log", "macos_workers", "mutex", "now", "paths",
    "read_gate", "refuse_if_disk_exhausted", "release_owner", "repair_stale_gate",
    "runner_is_stopped", "verify_participation", "work_volume", "write_atomic",
]
