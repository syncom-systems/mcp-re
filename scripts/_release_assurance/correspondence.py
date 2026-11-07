# SPDX-License-Identifier: Apache-2.0
"""CORRESPONDENCE: every provenance document is registered, and a mechanized one matches its record."""

from __future__ import annotations

from _release_assurance.config import BACKING, LEGACY_PRODUCED, MARKER_BEGIN, RELEASES
from _release_assurance.records import block_of, producer_problems, record_name, render


def _block_problems(name: str, block: str, expected: str) -> list[str]:
    if block.strip() == expected.strip():
        return []
    return [
        f"{RELEASES / name}'s assurance block disagrees with the record.\n"
        f"  document says:\n    " + "\n    ".join(block.strip().splitlines()) + "\n"
        f"  record says:\n    " + "\n    ".join(expected.strip().splitlines())
    ]


def _document_problems(name: str, document: str, records: dict[str, dict]) -> list[str]:
    backing = BACKING.get(name)
    if backing is None:
        return [
            f"{RELEASES / name} is not registered in BACKING. A release provenance "
            "document states an assurance verdict; one this gate has not been taught "
            "to check is a verdict nobody checks. Register it as `mechanized`."
        ]
    if backing == "pre-mechanism":
        return []
    block = block_of(document)
    if block is None:
        return [
            f"{RELEASES / name} is registered `mechanized` but carries no "
            f"`{MARKER_BEGIN}` block, so its assurance line is typed rather than derived."
        ]
    record = records.get(record_name(name))
    if record is None:
        return [
            f"{RELEASES / name} is `mechanized` and {RELEASES / record_name(name)} is "
            "absent, unreadable, or not a schema-2 release-assurance record. A missing "
            "record is a refusal, never a pass."
        ]
    found = producer_problems(record, legacy_ok=name in LEGACY_PRODUCED)
    if found:
        return [f"{RELEASES / record_name(name)}: {problem}" for problem in found]
    return _block_problems(name, block, render(record))


def correspondence_problems(documents: dict[str, str], records: dict[str, dict]) -> list[str]:
    """Every provenance document is registered, and a mechanized one matches its record."""
    problems: list[str] = []
    for name in sorted(documents):
        problems += _document_problems(name, documents[name], records)
    return problems
