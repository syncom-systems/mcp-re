# SPDX-License-Identifier: Apache-2.0
"""The one-shot upward-baseline rule: a raised `baseline_prod_loc` authorizes itself never."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from _module_size.config import REPO

import _ratchet  # noqa: E402
import _registries  # noqa: E402


def growth_authorization_line(rel: str, old: int, new: int) -> str:
    """The exact literal a §14 record must contain to authorize `old -> new` for `rel`.

    Path and BOTH integers, because each one is a thing the record has to have been written
    about. A record that says only "error.rs may grow" authorizes every future increase; a
    record that says only "442 -> 454" could be cited by any file.
    """
    return f"growth-authorization: {rel} {old} -> {new}"


def file_is_unchanged(rel: str, ref: str = "origin/main") -> bool | None:
    """Whether `rel` has the same bytes here as at `ref`. `None` when `ref` cannot be read.

    The discriminator between a file that GREW and a file that was MIS-MEASURED. Growth is a
    fact about the source; a measurement correction is a fact about this script. They are
    told apart by asking whether the source moved, which no one can answer in their own
    favour: to grow a file you must change it, and a changed file gets no correction.
    """
    try:
        blob = _registries.blob_at(rel, ref, REPO)
    except _registries.ManifestError:
        return None
    if blob is None:
        return None
    here = REPO / rel
    if not here.exists():
        return None
    return here.read_bytes() == blob


class Ledger(NamedTuple):
    """What a growth judgement reads besides the entry itself."""

    previous: dict[str, dict]
    measured: dict[str, int]
    root: Path
    unchanged: Callable[[str], bool | None] = file_is_unchanged


class Raise(NamedTuple):
    """An entry whose baseline moved up from `old` to `new`."""

    rel: str
    entry: dict
    old: int
    new: int


def _pairing_problem(rel: str) -> str:
    return (
        f"{rel}: `growth_from_prod_loc` and `growth_ref` are one authorization and "
        f"must appear together — a transition with no record is unevidenced, and a "
        f"record with no transition does not say which increase it authorized"
    )


def _spent_problems(rel: str, frm: object, new: int) -> list[str]:
    """No upward transition. A lingering authorization is the RECORD of the last one and
    is inert — but only while it describes a transition already spent. One that reaches
    the current baseline is stale, and a stale authorization is exactly what the one-shot
    rule exists to refuse."""
    if frm is None or int(frm) < new:
        return []
    return [
        f"{rel}: `growth_from_prod_loc` is {frm} and the baseline is {new} — a "
        f"spent authorization must sit strictly below the ceiling it bought; "
        f"remove it, the growth it recorded has been paid back"
    ]


def _is_measurement_correction(rel: str, entry: dict, new: int, ledger: Ledger) -> bool:
    """The narrow way to a raised baseline: this script's own counting changed, so the old
    baseline described a size the file never had.

    It is strictly weaker than an authorization — it buys nothing. The file's bytes must be
    identical to `origin/main`, so it cannot travel with an edit to the file it
    re-baselines, and the new baseline must EQUAL the measurement, so it grants no headroom:
    the file is pinned at its true size and still cannot grow by one line. Anyone wanting
    room has to come back through the authorization.

    It is a separate instrument rather than a lenient reading of the authorization because
    the authorization requires `status = "reviewed-exception"`, and a file that was merely
    counted wrong has not thereby been reviewed. Correcting a number must not launder a
    disposition.
    """
    actual = ledger.measured.get(rel)
    return (
        entry.get("growth_from_prod_loc") is None
        and actual is not None
        and actual == new
        and bool(ledger.unchanged(rel))
    )


def _record_problem(rel: str, ref: object, want: str, root: Path) -> str | None:
    """Whether a document named by `growth_ref` carries the authorization line."""
    named = _ratchet.documents(str(ref))
    if not named:
        return (
            f"{rel}: `growth_ref` names no document — cite the record's file so the "
            f"authorization can be read"
        )
    if any(
        (root / doc).exists()
        and want in (root / doc).read_text(encoding="utf-8", errors="replace")
        for doc in named
    ):
        return None
    return (
        f"{rel}: no document named by `growth_ref` contains the line "
        f"`{want}` — the record must authorize this exact transition, for this "
        f"exact file, in words a reader and this gate agree on"
    )


def _growth_problems(raised: Raise, ledger: Ledger) -> list[str]:
    """Growth, where every condition is required; they are reported together rather than
    at the first failure, so one run names the whole gap."""
    rel, entry, old, new = raised
    frm = entry.get("growth_from_prod_loc")
    if frm is None:
        return [
            f"{rel}: `baseline_prod_loc` was raised {old} -> {new} with no growth "
            f"authorization — a raised ceiling turns the ratchet off for this file, so "
            f"it needs an ADR-MCPRE-061 §14 record, not a larger integer"
        ]
    problems: list[str] = []
    if int(frm) != old:
        problems.append(
            f"{rel}: `growth_from_prod_loc` is {frm} but the baseline on origin/main is "
            f"{old} — an authorization is for one exact transition, and a spent one does "
            f"not authorize the next"
        )
    actual = ledger.measured.get(rel)
    if actual is not None and actual != new:
        problems.append(
            f"{rel}: the raised baseline is {new} but the file measures {actual} "
            f"production lines — an upward baseline authorizes exactly the growth that "
            f"happened, never headroom for growth that has not been reviewed"
        )
    status = entry.get("status")
    if status != "reviewed-exception":
        problems.append(
            f"{rel}: `baseline_prod_loc` was raised {old} -> {new} while status is "
            f"`{status}` — only a unit whose §14 census deliberately kept it INTACT may "
            f"grow; anything else is growing a unit already owed a decomposition"
        )
    record = _record_problem(
        rel, entry.get("growth_ref"), growth_authorization_line(rel, old, new), ledger.root
    )
    if record is not None:
        problems.append(record)
    return problems


def _baselines(entry: dict, before: dict | None) -> tuple[int, int] | None:
    """(old, new) for an entry that is a transition; None when it is not one.

    A newly registered entry is new debt (the threshold rules judge it) and a malformed
    one is the register schema's to report.
    """
    if before is None:
        return None
    old, new = before.get("baseline_prod_loc"), entry.get("baseline_prod_loc")
    if old is None or new is None:
        return None
    return int(old), int(new)


def _entry_problems(rel: str, entry: dict, ledger: Ledger) -> list[str]:
    frm = entry.get("growth_from_prod_loc")
    if (frm is None) != (entry.get("growth_ref") is None):
        return [_pairing_problem(rel)]

    pair = _baselines(entry, ledger.previous.get(rel))
    if pair is None:
        return []
    old, new = pair

    if new <= old:
        return _spent_problems(rel, frm, new)
    if _is_measurement_correction(rel, entry, new, ledger):
        return []
    return _growth_problems(Raise(rel, entry, old, new), ledger)


def check_baseline_growth(current: dict[str, dict], ledger: Ledger) -> list[str]:
    """Refuse an upward `baseline_prod_loc` transition that is not separately authorized.

    The per-file ratchet compares a file against its baseline. Nothing compared the
    BASELINE against anything, so raising it authorized itself — the ratchet's own input
    was writable by the party it constrains. This is the missing half, and it is
    deliberately the strictest rule in the package: a raised ceiling is the one edit that
    makes every other check weaker.

    An upward transition has two, and only two, ways through: a measurement correction, or
    an authorization naming this exact transition in a §14 record.
    """
    problems: list[str] = []
    for rel, entry in current.items():
        problems.extend(_entry_problems(rel, entry, ledger))
    return problems
