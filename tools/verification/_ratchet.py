# SPDX-License-Identifier: Apache-2.0
"""A ratchet register: a committed TOML table of debt that may only shrink, read now and
at the baseline revision it is held against.

Five gates hold a measured population against such a register:

    scripts/module_size_gate.py           config/module-size-debt.toml          [[debt]]
    scripts/unit_closure_gate.py          config/unit-closure-exclusions.toml   [[exclusion]]
    scripts/assurance_obligation_gate.py  config/assurance-obligation-debt.toml [[obligation]]
    scripts/doc_path_gate.py              config/doc-path-debt.toml             [[debt]]
    scripts/clippy_ratchet_gate.py        config/clippy-debt.toml               [[debt]]

This module owns what they share: reading the register, its schema (the entry key, the
required and permitted fields, the status vocabulary, and that a reviewed status names a
record that exists), and its BASELINE — the same register at `origin/main`. Each gate keeps
its own question: what it measures, which transitions it permits, and what may grow.

THE BASELINE HAS THREE STATES, and only one of them is a baseline:

    Present(entries)   the revision holds the register; compare against `entries`
    Absent()           the revision resolves and holds no register; nothing to compare
    Unreadable(reason) git could not answer; NOTHING HAS BEEN MEASURED

`Unreadable` is not `Absent`. A gate that reads "git failed" as "no register at the base"
skips its transition checks and reports green having compared nothing, so `at` never
collapses the two, and a gate that holds transitions refuses on `Unreadable`.
"""

from __future__ import annotations

import re
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _registries  # noqa: E402

REPO = Path(__file__).resolve().parents[2]

#: The base every register is held against, unless a gate is told otherwise.
BASE = "origin/main"


class RegisterError(Exception):
    """The register cannot be read as entries: unparsable TOML, or an entry with no key or
    the same key as another. Fatal, because a register that cannot be keyed cannot be
    compared with anything."""


@dataclass(frozen=True)
class Schema:
    """What an entry of one register must look like.

    `key` names the field that identifies an entry, or computes the identity from it.
    `fields` is the closed set of permitted fields; None leaves the set open. `statuses` is
    the disposition vocabulary, None for a register without dispositions, and the statuses
    in `reviewed` must carry a `review_ref` naming a record that exists.
    """

    table: str
    key: str | Callable[[dict], str]
    required: frozenset[str] = frozenset()
    fields: frozenset[str] | None = None
    statuses: tuple[str, ...] | None = None
    reviewed: frozenset[str] = frozenset()
    #: Appended to the unknown-field problem, for a field name a register is known to have
    #: carried under another name.
    unknown_hint: str = ""


@dataclass(frozen=True)
class Present:
    entries: dict[str, dict]


@dataclass(frozen=True)
class Absent:
    pass


@dataclass(frozen=True)
class Unreadable:
    reason: str


Baseline = Present | Absent | Unreadable


@dataclass(frozen=True)
class Register:
    """One register: `rel` under `root`, shaped by `schema`."""

    rel: str
    schema: Schema
    root: Path = field(default=REPO)

    @property
    def path(self) -> Path:
        return self.root / self.rel

    def exists(self) -> bool:
        return self.path.is_file()

    def current(self) -> dict[str, dict]:
        """The register as this tree has it. An absent file is an empty register."""
        if not self.exists():
            return {}
        return self.entries(self.path.read_text(encoding="utf-8"), self.rel)

    def entries(self, text: str, where: str) -> dict[str, dict]:
        """`text` as `{key: entry}`. Raises `RegisterError` on unparsable TOML, an entry
        with no key, or two entries under one key."""
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise RegisterError(f"{where}: unparsable: {exc}") from exc
        out: dict[str, dict] = {}
        for index, entry in enumerate(doc.get(self.schema.table, [])):
            label = f"{where} [[{self.schema.table}]] #{index + 1}"
            try:
                key = self._key(entry)
            except KeyError as exc:
                raise RegisterError(f"{label}: missing key field {exc}") from exc
            if key in out:
                raise RegisterError(f"{label}: duplicate entry {key!r}")
            out[key] = entry
        return out

    def _key(self, entry: dict) -> str:
        key = self.schema.key
        return str(entry[key]) if isinstance(key, str) else key(entry)

    def at(self, ref: str = BASE) -> Baseline:
        """The register at `ref`, in one of the three baseline states."""
        try:
            blob = _registries.blob_at(self.rel, ref, self.root)
        except _registries.ManifestError as exc:
            return Unreadable(str(exc))
        if blob is None:
            return Absent()
        try:
            return Present(self.entries(blob.decode("utf-8"), f"{ref}:{self.rel}"))
        except (RegisterError, UnicodeDecodeError) as exc:
            return Unreadable(str(exc))

    def problems(self, entries: dict[str, dict]) -> list[str]:
        """Every way `entries` departs from the schema, one sentence each."""
        out: list[str] = []
        for key, entry in sorted(entries.items()):
            out.extend(self._shape_problems(key, entry))
            if self.schema.statuses is not None:
                out.extend(self._status_problems(key, entry))
        return out

    def _shape_problems(self, key: str, entry: dict) -> list[str]:
        schema, table = self.schema, self.schema.table
        out = [
            f"{key}: {table} entry is missing `{name}`"
            for name in sorted(schema.required - set(entry))
        ]
        unknown = sorted(set(entry) - schema.fields) if schema.fields is not None else []
        if unknown:
            out.append(f"{key}: unknown {table} field(s) {unknown}{schema.unknown_hint}")
        return out

    def _status_problems(self, key: str, entry: dict) -> list[str]:
        status = entry.get("status")
        ref = str(entry.get("review_ref") or "").strip()
        out = self._vocabulary_problems(key, status)
        if status in self.schema.reviewed and not ref:
            out.append(
                f"{key}: status is `{status}` but no `review_ref` names the record that "
                f"adjudicated it"
            )
        if ref:
            out.extend(f"{key}: {p}" for p in review_ref_problems(ref, self.root))
        return out

    def _vocabulary_problems(self, key: str, status: object) -> list[str]:
        statuses = self.schema.statuses or ()
        if status is None or status in statuses:
            return []
        return [f"{key}: status `{status}` is not one of {sorted(statuses)}"]


def review_ref_problems(ref: str, root: Path) -> list[str]:
    """Why `ref` does not resolve to a record, or nothing when it does.

    A `review_ref` names one or more `.md` documents. When it also names a record — `EX-017
    in docs/architecture/review-dispositions.md` — the first document must contain that
    record id: a reference to a record that is not there is a memory of a review, not one.
    """
    named = documents(ref)
    if not named:
        return [
            "`review_ref` names no document — cite the record's file so the claim can be read"
        ]
    out = [
        f"`review_ref` names {doc}, which does not exist — a completed review must point at a "
        f"record, not at a memory of one"
        for doc in named
        if not (root / doc).is_file()
    ]
    if out:
        return out
    record = ref.split()[0]
    if record not in named and record not in (root / named[0]).read_text(encoding="utf-8"):
        out.append(f"`review_ref` names {record}, which {named[0]} does not contain")
    return out


def documents(ref: str) -> list[str]:
    """The repo-relative document paths a reference names."""
    return re.findall(r"\S+\.md", ref)


def transitions(
    previous: dict[str, dict], current: dict[str, dict]
) -> list[tuple[str, dict, dict]]:
    """`(key, before, after)` for every entry both registers hold, in key order.

    Only those are transitions. An entry that appears is new debt and one that disappears
    is paid debt; each gate's own rules judge those.
    """
    return [(key, previous[key], current[key]) for key in sorted(current) if key in previous]


def unreadable_problem(name: str, ref: str, baseline: Unreadable) -> str:
    """The refusal a gate holding transitions prints when its baseline is unreadable."""
    return (
        f"{name}: baseline unreadable at {ref} ({baseline.reason}) — the transition checks "
        f"compared nothing, and a check that did not run is not a pass. Fetch {ref} and re-run"
    )


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        from _ratchet_selftest import selftest

        sys.exit(selftest())
    sys.exit(0)
