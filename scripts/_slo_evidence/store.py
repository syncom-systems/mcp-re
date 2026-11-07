# SPDX-License-Identifier: Apache-2.0
"""The durable evidence store: where records live, how they are decided on and written."""

from __future__ import annotations

import json
import os
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from _slo_evidence import config
from _slo_evidence.config import LOCAL_STORE, REMEASURE, REPO, REUSE, SCHEMA, STORE_ENV
from _slo_evidence.context import context_digest, measurement_context, stale
from _slo_evidence.surface import performance_surface


def _write_atomic(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Write a durable record so a reader never observes a partial one.

    The store now outlives the process that writes it and is read by later, unrelated CI
    runs, so a truncated record is not a transient -- it is a permanently corrupt piece of
    evidence. `os.replace` is atomic within a filesystem, so a concurrent reader sees the
    old file or the new one.
    """
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(text, encoding=encoding)
    os.replace(tmp, path)


def evidence_store() -> Path:
    """The one resolved SLO evidence-store path.

    `MCP_RE_SLO_EVIDENCE_STORE` names a durable store outside the checkout (the owner's
    measurement host keeps one, so a clean checkout does not lose attested results);
    without it the records live in `REPO/.verification/slo`.
    """
    configured = os.environ.get(STORE_ENV)
    return Path(configured).expanduser() if configured else LOCAL_STORE


def record_path(surface: str, context: str) -> Path:
    return evidence_store() / f"{surface.split(':')[1][:16]}-{context.split(':')[1][:16]}.json"


def _missing_record_reason(surface: str) -> str:
    """Why nothing is attested at this identity.

    Three different reasons, and they are not interchangeable: one says nothing has ever
    been measured, one says the code moved, one says the box did.
    """
    store = evidence_store()
    prior = sorted(store.glob("*.json")) if store.is_dir() else []
    if not prior:
        return "no attested result exists for any performance surface"
    same_surface = [p for p in prior if json.loads(p.read_text())["performance_surface"] == surface]
    if not same_surface:
        return "the declared performance surface has MOVED since the last attested result"
    return ("the surface is attested, but in a DIFFERENT measurement context — "
            "a result measured elsewhere answers a different question")


def _judge_record(path: Path, max_age_days: int | None) -> tuple[str, str, int]:
    record = json.loads(path.read_text(encoding="utf-8"))
    declared = tomllib.loads(config.SURFACE_TOML.read_text(encoding="utf-8"))
    window = declared["freshness"]["max_age_days"]
    window = window if max_age_days is None else max_age_days
    recorded = datetime.fromisoformat(record["recorded_utc"])
    now = datetime.now(timezone.utc)
    age = now - recorded
    if stale(recorded, window, now):
        return "REMEASURE", f"the attested result is {age.days} days old, past the {window}-day window", REMEASURE
    if record["verdict"] != "PASS":
        return "REMEASURE", f"the attested result for this identity is {record['verdict']}", REMEASURE
    return (
        "REUSE",
        f"attested {recorded.date()} ({age.days}d old): {record['verdict']}, "
        f"median {record['median_throughput_rps']:.1f} rps over {len(record['reps'])} rep(s)",
        REUSE,
    )


def decide(max_age_days: int | None) -> tuple[str, str, int]:
    """`(verdict, reason, exit code)`. The reason is the point: it names which half moved."""
    surface, _ = performance_surface()
    digest = context_digest(measurement_context())
    path = record_path(surface, digest)
    if not path.is_file():
        return "REMEASURE", _missing_record_reason(surface), REMEASURE
    return _judge_record(path, max_age_days)


def _rep(report_path: str) -> dict[str, object]:
    results = json.loads(Path(report_path).read_text(encoding="utf-8"))["results"]
    return {
        "throughput_rps": results["throughput_rps"],
        "successes": results["successes"],
        "failures": results["failures"],
        "p99_added_us": results["added_latency_us"]["p99"],
    }


def _median(rates: list[float]) -> float:
    rates = sorted(rates)
    mid = len(rates) // 2
    return rates[mid] if len(rates) % 2 else (rates[mid - 1] + rates[mid]) / 2


def record(report_paths: list[str], verdict: str) -> int:
    surface, digests = performance_surface()
    context = measurement_context()
    digest = context_digest(context)
    reps = [_rep(path) for path in report_paths]
    if not reps:
        raise SystemExit("error: --record needs at least one report")
    evidence_store().mkdir(parents=True, exist_ok=True)
    path = record_path(surface, digest)
    document = {
        "schema": SCHEMA,
        "performance_surface": surface,
        "measurement_context": context,
        "measurement_context_digest": digest,
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "median_throughput_rps": _median([rep["throughput_rps"] for rep in reps]),
        "reps": reps,
        "surface_inputs": digests,
    }
    _write_atomic(path, json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    shown = path if not path.is_relative_to(REPO) else path.relative_to(REPO)
    print(f"recorded {verdict} for {surface[:23]}… / context {digest[:23]}… -> {shown}")
    return 0
