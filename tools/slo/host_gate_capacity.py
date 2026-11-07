"""Capacity admission: refuse a job on a volume with no room to run it.

This refusal protects CAPACITY, not a measurement, so unlike the rest of the arbiter it
fails OPEN on an unreadable volume: the guard declines to become the outage it exists to
prevent.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate_config as cfg  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402
from host_gate_state import log  # noqa: E402
from job_identity import JobIdentity  # noqa: E402

_WORK_VARS = ("RUNNER_WORKSPACE", "GITHUB_WORKSPACE", "RUNNER_TEMP")


def _nearest_existing(candidate: Path) -> Path | None:
    # The path need not exist yet this early in the job, so the nearest existing
    # ancestor is measured instead. That is the same volume EXCEPT where the intended
    # volume is not mounted at all -- in which case the job could not write there
    # either, and free space is not the interesting problem.
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate if candidate.exists() else None


def work_volume(env: dict[str, str] | None = None) -> Path | None:
    """The filesystem the job about to run will write to, or None if it cannot be named.

    Asked of the runner's own hook environment rather than assumed to be `/`. The same code
    runs inside the colima VM, which is a different kernel with a different filesystem, and
    nothing on the host prevents `_work` being moved to an external volume. A guard that
    measured the wrong volume would report a number that is true about some disk and
    irrelevant to this job -- which is worse than not measuring, because it reads as an
    answer.
    """
    e = dict(os.environ if env is None else env)
    for var in _WORK_VARS:
        value = e.get(var)
        found = _nearest_existing(Path(value)) if value else None
        if found is not None:
            return found
    return None


def free_gb(path: Path) -> float:
    """Free space on `path`'s volume, in the same unit the retention script reports.

    Divisor matched deliberately: DISK_REFUSE_GB and that script's LOW_SPACE_ALARM_GB
    describe one condition at two stages, and a mismatched divisor would put a 7% error
    between them for no reason.
    """
    return shutil.disk_usage(path).free / (1024.0**3)


def is_recovery(ident: JobIdentity) -> bool:
    """True only for the lane that makes the disk not-full.

    Repository AND workflow path, for the reason `JobIdentity.is_slo` uses both: a title
    match would let any workflow name itself into the exemption.
    """
    return (ident.repository == cfg.RECOVERY_REPOSITORY
            and ident.workflow_path == cfg.RECOVERY_WORKFLOW)


def _measured_free(p: dict[str, Path], ident: JobIdentity, measure) -> tuple[Path, float] | None:
    """The job's volume and its free space, or None (logged) when either is unknowable."""
    volume = work_volume()
    if volume is None:
        log(p, "capacity.unmeasured", key=ident.key,
            reason="no runner work path in the hook environment")
        return None
    try:
        return volume, (measure or free_gb)(volume)
    except OSError as exc:
        log(p, "capacity.unmeasured", key=ident.key, volume=str(volume), error=str(exc))
        return None


def _exhausted(volume: Path, free: float) -> ArbiterError:
    return ArbiterError(
        f"refusing admission: {volume} has {free:.1f} GB free, under the "
        f"{cfg.DISK_REFUSE_GB:.0f} GB floor this host admits work above. Fail-closed: this job "
        f"executed no workload, and nothing it would have written was written. The volume is "
        f"named because the runner and the colima VM measure different filesystems. To "
        f"reclaim: run the disk-retention workflow in matssun/code (exempt from this "
        f"refusal, so it still starts), or "
        f"`infrastructure/scripts/verification_store_retention.py --apply` on the host."
    )


def refuse_if_disk_exhausted(p: dict[str, Path], ident: JobIdentity, measure=None) -> None:
    """Refuse a job on a volume with no room to run it. The recovery lane is exempt.

    WHAT THIS CHANGES, WHICH IS NOT THE FREQUENCY OF A FULL DISK
    ------------------------------------------------------------
    Retention reduces how often the volume fills. This decides what HAPPENS when it does.

    On 2026-09-01 the volume reached 167 MB free. dev1-linux went on reporting `online` to
    GitHub and accepting jobs it could not run, for a fortnight, because nothing on the
    admission path had an opinion about capacity. The jobs did not fail cleanly -- the VM
    wedged, sixteen `colima ssh` grandchildren orphaned, and the machine looked healthy from
    every angle an operator would think to check.

    A refusal here is a red job naming the volume and the number. That is a worse-looking
    outcome and a far better one: it is attributable, it points at its own remedy, and it
    arrives on the first job rather than whenever somebody happens to look.

    WHY THIS ONE FAILS OPEN WHEN THE REST OF THE ARBITER FAILS CLOSED
    ----------------------------------------------------------------
    Every other refusal in this file protects a MEASUREMENT: admitting wrongly corrupts an
    SLO number, so uncertainty must refuse. This one protects CAPACITY, where the asymmetry
    runs the other way -- refusing wrongly stops all work on the host for no reason at all.
    So an unreadable volume is logged and admitted. The guard declines to become the outage
    it exists to prevent.
    """
    measured = _measured_free(p, ident, measure)
    if measured is None:
        return
    volume, free = measured
    if free >= cfg.DISK_REFUSE_GB:
        log(p, "capacity.ok", key=ident.key, volume=str(volume), free_gb=round(free, 1))
    elif is_recovery(ident):
        log(p, "capacity.recovery_admitted", key=ident.key, volume=str(volume),
            free_gb=round(free, 1))
    else:
        raise _exhausted(volume, free)
