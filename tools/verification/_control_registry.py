# SPDX-License-Identifier: Apache-2.0
"""Registry-carried controls (structural, mutation, measurement) and the gate controls."""

from __future__ import annotations

from pathlib import Path

import _gates
import _registries
from _control_model import Control
from _ecosystems import REPO_ROOT

#: `(registry, table, kind)` for each registry whose records are executed by their own lane.
_REGISTRY_KINDS = (
    ("structural-probes", "probe", "structural"),
    ("mutation-probes", "probe", "mutation"),
    ("measurements", "measurement", "measurement"),
)


def probe_controls() -> list[Control]:
    """`structural://` and `mutation://` probes, and `measured://` measurements.

    These are controls with an executable carrier — their lane runs each record — and an
    identity the registry already assigns, so they join to a unit by the probe's own
    `unit` field rather than through a symbol list.
    """
    return [
        Control(
            project="",
            identity=f"{kind}#{row['id']}",
            kind=kind,
            carrier=_registries.relative(registry),
            line=0,
        )
        for registry, table, kind in _REGISTRY_KINDS
        for row in _registries.rows(registry, table)
    ]


def gate_controls(root: Path = REPO_ROOT) -> list[Control]:
    """The source-text and structural gates under `scripts/`.

    A gate is a control by every test this record applies: it executes on the merge path,
    it can fail, and what it refuses is a security-relevant property. Whether any unit
    CLAIMS one is exactly ADR-069's question.

    The population is every `scripts/*.py|*.sh` except a script the gate registry
    (`config/gates.toml`, read by `_gates`) marks `not_a_control` — a driver, runner,
    report, demo or repository operation, with its reason recorded there once. A script
    with no row stays in the population, so a missing row can only widen the census; the
    merge-path gate is what refuses the missing row. An unreadable registry raises
    `_gates.RegistryError` rather than yielding a narrower census.
    """
    not_controls = _gates.not_controls(_gates.load(root))
    return [
        Control(
            project="",
            identity=f"gate#{path}",
            kind="gate",
            carrier=path,
            line=0,
        )
        for path in sorted(_gates.population(root) - not_controls)
    ]
