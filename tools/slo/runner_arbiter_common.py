"""What every `runner_arbiter` command shares: exit codes and the VM observation probes."""

from __future__ import annotations

from pathlib import Path

import host_gate
import vm_participant
from arbiter_error import ArbiterError

EXIT_OK, EXIT_REFUSED, EXIT_INCONSISTENT = 0, 1, 3


def vm_workers_or_refuse():
    """The drain loop's VM observation. An unreachable VM refuses; it never reads as idle."""
    def probe() -> int:
        if not vm_participant.available():
            if vm_participant.stopped():
                return 0  # Lima reports it Stopped: it runs nothing
            raise ArbiterError(
                "the colima VM hosting dev1-linux is unreachable, so its runner cannot be "
                "observed. Refusing: an unobserved runner is not a quiet runner."
            )
        return vm_participant.worker_count()
    return probe


def vm_readers() -> host_gate.VmProbes:
    """Participation probes; `read_env=None` when the VM cannot be reached at all."""
    if not vm_participant.available():
        return host_gate.VmProbes(stopped=vm_participant.stopped())
    return host_gate.VmProbes(read_env=lambda path: vm_participant.read_file(path),
                              check_exec=vm_participant.is_executable,
                              check_fresh=vm_participant.listener_loaded_env)


def inhibition_file(paths) -> Path:
    """The proof that the VM runner was stopped instead of gating itself."""
    return paths["root"] / "vm-inhibition.json"


def release_inhibition(paths) -> None:
    """Release the VM stop this arbiter applied, and only that."""
    vm_participant.release_fallback()
    inhibition_file(paths).unlink(missing_ok=True)
