# SPDX-License-Identifier: Apache-2.0
"""The declared hardware classes: the vocabulary, each class's anchor, and its defects."""

from __future__ import annotations

import json
import tomllib
from typing import NamedTuple

from _slo_evidence import config
from _slo_evidence.config import CLASS_KEYS, REPO, TARGETS

PERCENTILE_FRACTIONS = (
    ("p50", "p50_added_us_max_fraction"),
    ("p99", "p99_added_us_max_fraction"),
    ("p999", "p999_added_us_max_fraction"),
)


def _declared_classes() -> list[dict]:
    return tomllib.loads(config.SURFACE_TOML.read_text(encoding="utf-8"))["context"]["class"]


def hardware_classes() -> dict[str, dict[str, object]]:
    """The declared measurement contexts, by `hardware_class` value.

    The one vocabulary. `adr051_slo_gate.py` asks it which anchor a report may be compared
    against, `slo_gate.py` asks it which classes can never be an absolute SLO verdict, and
    `--runner-class` reports what the controlled measurement host measures as. A class absent from here
    is not an error in itself — an unrecognised class simply has no anchor and no
    declarability — but it is what those gates read instead of each keeping its own list.
    """
    return {entry["name"]: entry for entry in _declared_classes()}


def runner_class() -> str:
    """The class the controlled measurement host (dev1) measures as.

    Exactly one entry may claim it. Callers read this rather than restating the name,
    for the reason `config/ports.toml` exists: a literal in a second place is a fact that
    can drift, and a drifted class name would key a record to a context nobody declared.
    """
    claimed = [name for name, entry in hardware_classes().items() if entry["github_actions_runner"]]
    if len(claimed) != 1:
        raise SystemExit(
            f"error: exactly one [[context.class]] must set github_actions_runner = true; "
            f"{len(claimed)} do ({claimed})"
        )
    return claimed[0]


class _Anchor(NamedTuple):
    """A class's committed anchor: its results, the reps that defined it, the tolerances."""

    name: str
    results: dict
    reps: dict
    tolerances: dict


def _load_anchor(name: str, entry: dict, tolerances: dict) -> _Anchor | None:
    anchor_path = entry.get("regression_anchor")
    if not anchor_path or not (REPO / anchor_path).is_file():
        return None
    results = json.loads((REPO / anchor_path).read_text(encoding="utf-8"))["anchor"]["results"]
    reps = results.get("reps") or {}
    return _Anchor(name, results, reps, tolerances) if reps else None


def _throughput_defects(anchor: _Anchor) -> list[str]:
    floor = anchor.results["throughput_rps"] * anchor.tolerances["throughput_rps_min_fraction"]
    under = [r for r in anchor.reps.get("throughput_rps", []) if r < floor]
    if not under:
        return []
    return [
        f"{anchor.name!r}: throughput reps {under} fall below the floor {floor:.1f} its own "
        f"anchor produces"
    ]


def _percentile_defects(anchor: _Anchor, percentile: str, fraction_key: str) -> list[str]:
    ceiling = anchor.results["added_latency_us"][percentile] * anchor.tolerances[fraction_key]
    over = [r for r in anchor.reps.get(f"{percentile}_us", []) if r > ceiling]
    if not over:
        return []
    return [
        f"{anchor.name!r}: {percentile} reps {over} exceed the ceiling {ceiling:.0f} its "
        f"own anchor produces — the band is narrower than the spread it was "
        f"declared from, so the gate would reject a run like the one that "
        f"defined it. Re-measure on a quieter host rather than widening the "
        f"tolerance."
    ]


def _anchor_defects(anchor: _Anchor) -> list[str]:
    found = _throughput_defects(anchor)
    for percentile, fraction_key in PERCENTILE_FRACTIONS:
        found += _percentile_defects(anchor, percentile, fraction_key)
    return found


def anchor_consistency_defects() -> list[str]:
    """An anchor must ADMIT the measurements that declared it.

    THE DEFECT THIS CATCHES, found by shipping it. `dev1-slo-v1`'s first anchor was the
    MEDIAN of six reps, and the gate derives its ceiling by multiplying that median by the
    declared tolerance. But the rep-to-rep spread of p99 on a co-located loadgen is wider
    than the tolerance: median 20,937us gave a ceiling of 27,218us, while one of the six
    reps that DEFINED the anchor measured 29,772us. The gate was therefore flaky by
    construction -- it would reject a run indistinguishable from the one it was built from,
    and it did, on the very next measurement, at 1.1% over.

    A point estimate is a legitimate anchor only when the band around it covers the
    dispersion of the sample it came from. So the check is exactly that: run the gate's own
    arithmetic against the anchor's own reps. Any rep outside the band means the anchor
    cannot be used to adjudicate its own class.

    The remedy is NOT to widen the tolerance, which would weaken the gate everywhere to
    accommodate one noisy class. It is to re-measure on a host quiet enough that the spread
    fits the band -- which is what the tolerance file already says: "tighten them once a
    dedicated loadgen removes that noise."
    """
    tolerances = json.loads(TARGETS.read_text(encoding="utf-8"))["local_regression"]["tolerances"]
    found: list[str] = []
    for name, entry in hardware_classes().items():
        anchor = _load_anchor(name, entry, tolerances)
        if anchor is not None:
            found += _anchor_defects(anchor)
    return found


def _anchor_problems(name: str, anchor: str | None) -> list[str]:
    if not anchor:
        return []
    if not (REPO / anchor).is_file():
        return [f"{name!r} names regression_anchor {anchor!r}, which does not exist"]
    anchor_class = json.loads((REPO / anchor).read_text(encoding="utf-8"))["anchor"]["config"]["hardware_class"]
    if anchor_class == name:
        return []
    return [
        f"{name!r} names an anchor recorded on hardware_class {anchor_class!r} — "
        f"an anchor for a class must be a measurement of that class"
    ]


def _entry_defects(entry: dict, seen: set[str]) -> list[str]:
    missing = [key for key in CLASS_KEYS if key not in entry]
    if missing:
        return [f"[[context.class]] {entry.get('name', '?')!r} is missing {missing}"]
    name = entry["name"]
    found = [f"[[context.class]] declares {name!r} twice"] if name in seen else []
    seen.add(name)
    if not entry["slo_declarable"] and not entry.get("reason"):
        found.append(f"{name!r} is not slo_declarable and states no reason")
    return found + _anchor_problems(name, entry["regression_anchor"])


def class_defects() -> list[str]:
    """Shape problems in the declared class vocabulary."""
    declared = _declared_classes()
    found: list[str] = []
    seen: set[str] = set()
    for entry in declared:
        found += _entry_defects(entry, seen)
    claimed = [entry["name"] for entry in declared if entry.get("github_actions_runner")]
    if len(claimed) != 1:
        found.append(f"exactly one class must set github_actions_runner = true; {claimed} do")
    found.extend(anchor_consistency_defects())
    return found
