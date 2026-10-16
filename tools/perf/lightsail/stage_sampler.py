# SPDX-License-Identifier: Apache-2.0
"""The proxy's own stage timers, sampled while a rig rung runs.

The proxy writes cumulative per-stage sums when `MCP_RE_STAGE_TIMERS` names a path
(`mcp-re-proxy/src/stage_timers`): one CSV row per stage — `stage,count,total_ms,mean_us` —
rewritten every 5,000 completed requests, plus `replay_inflight,<samples>,<max>,<mean>` for
the replay calls in flight. Under `redis-wait-quorum` the `replay_wait` row times the whole
pipelined `SET NX PX` + `WAIT` round trip as the proxy sees it, queueing behind other WAITs
on the same connection included; `scheduler_latency` is how long a freshly spawned task
waited for a serving runtime to poll it.

The proxy creates the file itself (`create_new`), so nothing here creates or touches it: the
sampler reads it every 0.25 s and records each snapshot with a timestamp. A window's mean is
the difference of two cumulative snapshots, so a mean can be cut to one generator step.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

#: Read by the proxy; the harness sets it per rung, to a path that does not exist yet.
STAGE_TIMERS_ENV = "MCP_RE_STAGE_TIMERS"


def parse(text: str) -> dict[str, list[float]] | None:
    """{stage: [count, total_ms, mean_us]} from one snapshot, None for a partial write."""
    lines = text.strip().splitlines()
    if not lines or lines[0] != "stage,count,total_ms,mean_us":
        return None
    out = {}
    for line in lines[1:]:
        parts = line.split(",")
        if len(parts) != 4:
            return None
        try:
            out[parts[0]] = [float(x) for x in parts[1:]]
        except ValueError:
            return None
    return out if "replay_wait" in out else None


def window_means(samples: list[dict], start: float, end: float) -> dict:
    """Per-stage mean (us) and mean replay calls in flight between the first and last
    snapshot of ONE file inside [start, end]."""
    inside = [s for s in samples if start <= s["t"] <= end]
    if len(inside) < 2 or inside[0]["file"] != inside[-1]["file"]:
        return {"available": False, "reason": f"{len(inside)} snapshot(s) in the window"}
    a, b = inside[0]["stages"], inside[-1]["stages"]
    means = {}
    for stage, (count, total_ms, _mean) in b.items():
        if stage == "replay_inflight" or stage not in a:
            continue
        n = count - a[stage][0]
        means[stage] = (total_ms - a[stage][1]) * 1000 / n if n > 0 else None
        means[f"{stage}_count"] = n
    if "replay_inflight" in a and "replay_inflight" in b:
        (n0, _, m0), (n1, peak, m1) = a["replay_inflight"], b["replay_inflight"]
        means["replay_inflight_mean"] = (m1 * n1 - m0 * n0) / (n1 - n0) if n1 > n0 else None
        means["replay_inflight_peak_to_date"] = peak
    return {"available": True, "snapshots": len(inside), **means}


class Sampler(threading.Thread):
    """Polls whichever stage-timer file the current rung named (`self.path`)."""

    def __init__(self, out: Path, period: float = 0.25):
        super().__init__(daemon=True)
        self.out, self.period = out, period
        self.path: Path | None = None
        self.stop_event = threading.Event()
        self.samples: list[dict] = []

    def run(self) -> None:
        last = None
        with open(self.out, "w") as sink:
            while not self.stop_event.wait(self.period):
                path = self.path
                if path is None or not path.is_file():
                    continue
                try:
                    stages = parse(path.read_text())
                except OSError:
                    continue
                if stages is None or stages == last:
                    continue
                last = stages
                sample = {"t": time.time(), "file": path.name, "stages": stages}
                sink.write(json.dumps(sample) + "\n")
                sink.flush()
                self.samples.append(sample)


class Window:
    """Context manager around one point; disabled (records nothing) when `enabled` is False."""

    def __init__(self, point_dir: Path, enabled: bool):
        self.enabled = enabled
        self.sampler = Sampler(point_dir / "stage-timers.jsonl") if enabled else None

    def path_for(self, rung_file: Path) -> Path | None:
        """Point the sampler at the next rung's file; the env value for that rung, or None."""
        if self.sampler is None:
            return None
        self.sampler.path = rung_file
        return rung_file

    def __enter__(self) -> "Window":
        if self.sampler is not None:
            self.sampler.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.sampler is not None:
            self.sampler.stop_event.set()
            self.sampler.join(timeout=10)

    def summary(self, windows: list[list[float]]) -> dict:
        if self.sampler is None:
            return {"available": False, "reason": "stage timers off for this run"}
        if not windows:
            return {"available": False, "reason": "no window"}
        return window_means(self.sampler.samples, windows[-1][0], windows[-1][1])
