# SPDX-License-Identifier: Apache-2.0
"""The gate's whole verdict over the units it reads, optionally with some text overridden."""

from __future__ import annotations

from _refusal_provenance.cause import cause_problems, wildcard_problems
from _refusal_provenance.config import CORE_AUDIT, RECORD, REFUSAL, SERVING, TRANSPORT
from _refusal_provenance.lifecycle import (
    disposition_problems,
    handle_problems,
    minted_problems,
    transport_problems,
)
from _refusal_provenance.record import (
    audit_token_problems,
    core_audit_problems,
    facet_projection_problems,
    record_problems,
)
from _refusal_provenance.sources import read, read_unit
from _refusal_provenance.workspace import workspace_scan


def check(overrides: dict[str, str] | None = None) -> list[str]:
    refusal = "\n".join(read(r, overrides) for r in REFUSAL)
    serving = read_unit(SERVING, overrides)
    problems = cause_problems(refusal, serving)
    walked, transport_callers = workspace_scan(overrides)
    problems += walked
    problems += record_problems(read_unit(RECORD, overrides))
    problems += facet_projection_problems(serving)
    problems += core_audit_problems(read(CORE_AUDIT, overrides))
    problems += audit_token_problems(serving)
    problems += minted_problems(serving)
    problems += handle_problems(serving)
    problems += transport_problems(transport_callers, read(TRANSPORT, overrides))
    problems += disposition_problems(serving)
    problems += wildcard_problems(refusal)
    return problems
