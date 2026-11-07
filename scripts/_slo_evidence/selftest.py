# SPDX-License-Identifier: Apache-2.0
"""The identity is content-addressed, twice over: each property is asserted, not assumed."""

from __future__ import annotations

import tomllib
from datetime import datetime, timedelta, timezone

from _slo_evidence import config
from _slo_evidence.classes import class_defects, hardware_classes, runner_class
from _slo_evidence.context import context_digest, stale
from _slo_evidence.store import record_path
from _slo_evidence.surface import fold, performance_surface


def _surface_fold() -> tuple[str, dict[str, str]]:
    surface, digests = performance_surface()
    assert surface.startswith("sha256:") and digests, "the surface fold produced nothing"
    again, _ = performance_surface()
    assert again == surface, "the fold is not deterministic"

    # The fold must be sensitive to CONTENT, not merely to the file list: a fold over paths
    # alone would report an unchanged surface across every edit ever made to the code.
    perturbed = dict(digests)
    perturbed[sorted(perturbed)[0]] = "sha256:" + "0" * 64
    assert fold(perturbed) != surface, "the fold ignores content"
    return surface, digests


def _context_digests() -> None:
    declared = tomllib.loads(config.SURFACE_TOML.read_text(encoding="utf-8"))["context"]["fields"]
    context = {field: field for field in declared}
    digest = context_digest(context)
    moved = dict(context, hardware_class="something-else")
    assert context_digest(moved) != digest, "the context digest ignores the hardware class"
    # A field the declaration does not name must not move the digest — otherwise every
    # incidental key an environment adds would silently force a re-measurement.
    assert context_digest(dict(context, unnamed="x")) == digest, "the context digest reads undeclared fields"
    try:
        context_digest({"hardware_class": "x"})
        raise AssertionError("a context missing declared fields was accepted")
    except SystemExit:
        pass


def _freshness_and_paths() -> None:
    now = datetime(2026, 9, 8, tzinfo=timezone.utc)
    assert not stale(now - timedelta(days=89), 90, now), "a record inside the window went stale"
    assert not stale(now - timedelta(days=90), 90, now), "the boundary day is inside the window"
    assert stale(now - timedelta(days=91), 90, now), "a record past the window stayed fresh"

    a = record_path("sha256:" + "a" * 64, "sha256:" + "b" * 64)
    assert a != record_path("sha256:" + "a" * 64, "sha256:" + "c" * 64), "one surface collapses two contexts"


def _class_vocabulary() -> int:
    """The runner's class must resolve to exactly one name, and a class that claims an anchor
    must claim one measured on ITSELF — the cross-class comparison `adr051_slo_gate.py` now
    refuses is the same error one level up, made in the declaration instead of in the gate."""
    classes = hardware_classes()
    assert classes, "the declaration names no hardware class"
    assert runner_class() in classes, "the runner's class is not declared"
    assert not classes[runner_class()]["slo_declarable"], (
        "a co-located self-hosted runner was declared able to carry an absolute SLO verdict"
    )
    assert not class_defects(), f"the declared classes are malformed: {class_defects()}"
    return len(classes)


def selftest() -> int:
    _, digests = _surface_fold()
    _context_digests()
    _freshness_and_paths()
    classes = _class_vocabulary()
    print(
        f"slo_evidence_identity selftest: OK — {len(digests)} declared inputs, 9 identity "
        f"cases, {classes} hardware classes"
    )
    return 0
