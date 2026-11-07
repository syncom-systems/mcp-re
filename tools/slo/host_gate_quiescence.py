"""Quiescence: the host must stay quiet across consecutive samples, not at one instant.

One instantaneous `load1` cannot carry a release-grade claim, so all three load averages are
read and the condition must HOLD across `Q_SAMPLES` consecutive observations.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate_config as cfg  # noqa: E402
from host_gate_state import now  # noqa: E402


def _thresholds(ncpu: int) -> tuple[float, float, float]:
    return ncpu * cfg.Q_LOAD1, ncpu * cfg.Q_LOAD5, ncpu * cfg.Q_LOAD15


def _sample(loads: tuple[float, float, float], limits: tuple[float, float, float]) -> dict:
    l1, l5, l15 = loads
    return {"at": now(), "l1": round(l1, 2), "l5": round(l5, 2), "l15": round(l15, 2),
            "quiet": all(load <= limit for load, limit in zip(loads, limits))}


def await_quiescence(wait_s: int = cfg.Q_WAIT_S, loadavg=os.getloadavg, sleep=time.sleep) -> dict:
    ncpu = os.cpu_count() or 1
    limits = _thresholds(ncpu)
    started = time.monotonic()
    deadline = started + wait_s
    samples: list[dict] = []
    consecutive = 0
    while True:
        samples.append(_sample(loadavg(), limits))
        consecutive = consecutive + 1 if samples[-1]["quiet"] else 0
        base = {"ncpu": ncpu,
                "thresholds": {"load1": limits[0], "load5": limits[1], "load15": limits[2]},
                "consecutive_required": cfg.Q_SAMPLES,
                "duration_s": round(time.monotonic() - started, 1)}
        if consecutive >= cfg.Q_SAMPLES:
            return {"established": True, **base, "samples": samples}
        if time.monotonic() >= deadline:
            return {"established": False, **base, "samples": samples[-24:]}
        sleep(cfg.Q_INTERVAL_S)
