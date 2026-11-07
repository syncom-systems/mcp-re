# SPDX-License-Identifier: Apache-2.0
"""The gate's whole verdict over a set of workflow texts, and the inputs it is judged against."""

from __future__ import annotations

from _verification_trigger.config import REPO, WORKFLOWS  # noqa: I001  (puts tools/verification on sys.path)

from _fingerprint import fingerprint_read_set
from _assumptions import load_assumptions
from _manifest import load_verification
from _registry_refs import structural_probe_paths
from _toolchain_lock import load_toolchains
from _trust_boundaries import load_trust_boundaries
import _registries

from _verification_trigger.complete_run import check_complete_run
from _verification_trigger.paths import check_controls, check_indirect, check_merge_path, stale_filters
from _verification_trigger.probe import check_bounded_probe


def all_failures(texts: dict[str, str], deferral, required: list[str]) -> list[str]:
    failures = check_complete_run(texts["verification.yml"])
    failures += check_bounded_probe(texts["mutation-probe.yml"])
    failures += check_merge_path(texts["pre-merge.yml"], texts["post-merge.yml"])
    failures += check_indirect(texts)
    failures += check_controls(texts["verification.yml"], texts["mutation-probe.yml"], deferral)
    failures += [
        f"mutation-probe.yml path filter {p!r} names nothing in the tree"
        for p in stale_filters(texts["mutation-probe.yml"], REPO, required)
    ]
    return failures


def read_texts() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml"))}


def fingerprint_inputs() -> list[str]:
    doc, toolchains = load_verification(), load_toolchains()
    assumptions, boundaries = load_assumptions(), load_trust_boundaries()
    required: set[str] = set()
    for unit in doc.get("unit", []):
        required |= fingerprint_read_set(unit, doc, toolchains, assumptions, boundaries)
    required |= set(structural_probe_paths(_registries.rows("structural-probes", "probe")))
    return sorted(required)
