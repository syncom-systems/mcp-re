"""The escalated ledger rows, folded and grouped into the decisions a human answers.

Several findings usually wait on ONE decision, and evaluators mark the duplicates as they go.
`build_queue` folds a row whose note says "duplicate of <id>" under that id, then groups what
is left by `ruling_id` across files (an escalation without one is grouped by file). A
`ruling_id` prefixed `owner-signature:` is a ratification, not a choice, and is listed apart.
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DUP = re.compile(r"duplicate of ([0-9a-f]{8,})", re.I)
SIGN = "owner-signature:"
SEV_NAME = {v: k.upper() for k, v in SEV.items()}


def rank(row: dict) -> int:
    """Severity as a sort key: most severe first, unknown last."""
    return SEV.get(str(row.get("severity", "")).lower(), 9)


def worst(rows: list[dict]) -> int:
    return min(rank(r) for r in rows)


def path_of(row: dict):
    return row.get("path") or row.get("file")


@dataclass
class Queue:
    escalated: list[dict]
    folded: dict[str, list[dict]]
    primary: dict[str, dict]
    by_file: dict
    by_ruling: dict[str, list[dict]]

    @property
    def signature(self) -> list[str]:
        keys = sorted(k for k in self.by_ruling if k.startswith(SIGN))
        return sorted(keys, key=lambda k: (worst(self.by_ruling[k]), k))

    @property
    def decisions(self) -> list[str]:
        return sorted((k for k in self.by_ruling if not k.startswith(SIGN)),
                      key=lambda k: (worst(self.by_ruling[k]), k))

    @property
    def files(self) -> set:
        return {path_of(r) for r in self.primary.values()}


def load_rows(ledger: str) -> list[dict]:
    with open(ledger, encoding="utf-8") as fh:
        return [json.loads(line) for line in (raw.strip() for raw in fh) if line]


def _fold(escalated: list[dict]) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    """A row whose note says "duplicate of <id>" waits on that id's ruling."""
    folded: dict[str, list[dict]] = defaultdict(list)
    primary: dict[str, dict] = {}
    for r in sorted(escalated, key=rank):
        m = DUP.search(r.get("notes") or "")
        if m and m.group(1) != r["id"]:
            folded[m.group(1)].append(r)
        else:
            primary[r["id"]] = r
    _adopt_orphans(folded, primary)
    return folded, primary


def _adopt_orphans(folded: dict[str, list[dict]], primary: dict[str, dict]) -> None:
    """A fold target that is not itself escalated becomes its own decision."""
    for target, kids in list(folded.items()):
        if target not in primary:
            del folded[target]
            primary[kids[0]["id"]] = kids[0]
            folded[kids[0]["id"]] = kids[1:]


def build_queue(rows: list[dict], since: str | None) -> Queue:
    escalated = [r for r in rows if str(r.get("status", "")).lower() == "escalated"]
    if since:
        escalated = [r for r in escalated if since in (r.get("rounds") or [])]
    folded, primary = _fold(escalated)
    by_file: dict = defaultdict(list)
    by_ruling: dict[str, list[dict]] = defaultdict(list)
    for r in primary.values():
        if r.get("ruling_id"):
            by_ruling[r["ruling_id"]].append(r)
        else:
            by_file[path_of(r)].append(r)
    return Queue(escalated, folded, primary, by_file, by_ruling)


def load_blocked_on(packages: str | None) -> dict[str, str]:
    """The evaluator that read a file usually states, once, the single decision its
    escalations wait on. That is a truer unit than one decision per finding."""
    blocked_on: dict[str, str] = {}
    if not (packages and os.path.isdir(packages)):
        return blocked_on
    for name in sorted(os.listdir(packages)):
        if name.endswith(".json"):
            _read_package(os.path.join(packages, name), blocked_on)
    return blocked_on


def _read_package(path: str, blocked_on: dict[str, str]) -> None:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return
    stated = (doc.get("blocked_on") or "").strip()
    if doc.get("file") and stated:
        blocked_on[doc["file"]] = stated
