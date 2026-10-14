# SPDX-License-Identifier: Apache-2.0
"""The committed assurance-closure record — issue #1173 (MCPRE-220).

A closure record states one historical proposition:

    target tree T closed assurance at these exact content identities.

It is DERIVED evidence, not a human approval, so it lives under `verification/closures/`
and never under `verification/reviews/`. It keeps every per-unit and per-theorem identity,
not only aggregate digests, so a later mismatch can name the identity that moved. It stays
tens of kilobytes: the attestation store it was derived from is not persisted.

What it can never do is establish anything about another tree. It is not an attestation
store: no row carries the `unit_id` / `fingerprint` pair `_graph.Attestation` reads, so
`_graph.load_attestations` drops it, and no reader in the freshness graph looks in
`verification/closures/`. A later tree may be COMPARED with a record and reported identical
or different at each identity; being identical is a report, never freshness. Freshness for
a later tree comes only from attestations issued for that tree.

Two checks, kept apart:

  `problems` + `verify`   the record is well formed, its aggregate digests are the digests
                          of the identities it lists, and its target commit resolves to its
                          target tree. This stays true however far `main` advances.
  `compare`               which identities of the record differ from a tree's identities
                          as `review --json` derives them now.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

SCHEMA_VERSION = 1
KIND = "mcp-re.assurance-closure-record"
SUBJECT = "repository assurance closure"
DIRECTORY = Path("verification") / "closures"

_KEYS = {
    "schema_version",
    "kind",
    "subject",
    "verdict",
    "target",
    "run",
    "policy_revision",
    "review_ledger",
    "units",
    "units_digest",
    "theorems",
    "theorems_digest",
    "roots",
    "counts",
}


def canonical_digest(rows: list[dict]) -> str:
    """sha256 over the canonical JSON of `rows`: sorted keys, no whitespace."""
    text = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _unit_rows(review: dict) -> list[dict]:
    units = review["identities"]["units"]
    return [{"unit": unit, "fingerprint": units[unit]} for unit in sorted(units)]


def _theorem_rows(review: dict) -> list[dict]:
    theorems = review["identities"]["theorems"]
    active = sorted(t for t, state in review["theorems"].items() if not state["deprecated"])
    return [
        {
            "theorem": theorem,
            "fingerprint": theorems[theorem]["fingerprint"],
            "review_digest": theorems[theorem]["review_digest"],
        }
        for theorem in active
    ]


def build(closure: dict, review: dict) -> dict:
    """The record for one PASSING closure, from its decision and the `review --json` it read."""
    if closure.get("verdict") != "PASS":
        raise ValueError("a closure record is written only for a PASS")
    units, theorems = _unit_rows(review), _theorem_rows(review)
    roots = review["root_completeness"]
    counts = closure["counts"]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "subject": SUBJECT,
        "verdict": closure["verdict"],
        "target": {"commit": closure["target"]["commit"], "tree": closure["target"]["tree"]},
        "run": {
            "id": str(closure["run"]["id"]),
            "attempt": str(closure["run"]["attempt"]),
            "event": closure["run"]["event"],
            "evidence_commit": closure["run"]["evidence_commit"],
        },
        "policy_revision": review["identities"]["policy_revision"],
        "review_ledger": review["identities"]["review_ledger"],
        "units": units,
        "units_digest": canonical_digest(units),
        "theorems": theorems,
        "theorems_digest": canonical_digest(theorems),
        "roots": {"declared": list(roots["roots"]), "verdict": roots["verdict"]},
        "counts": {
            "active": counts["active"],
            "review_current": counts["review_current"],
            "evidence_established": counts["evidence_established"],
            "currently_verified": counts["currently_verified"],
            "roots": counts["roots"],
            "roots_established": counts["roots_established"],
        },
    }


def dumps(record: dict) -> str:
    """Sorted keys, one unit or theorem per line: compact, and a diff names the row."""
    lines = ["{"]
    keys = sorted(record)
    for index, key in enumerate(keys):
        value = record[key]
        comma = "," if index < len(keys) - 1 else ""
        if isinstance(value, list) and value and isinstance(value[0], dict):
            rows = [json.dumps(row, sort_keys=True) for row in value]
            lines.append(f"  {json.dumps(key)}: [")
            lines.extend(f"    {row}{',' if i < len(rows) - 1 else ''}" for i, row in enumerate(rows))
            lines.append(f"  ]{comma}")
        else:
            lines.append(f"  {json.dumps(key)}: {json.dumps(value, sort_keys=True)}{comma}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def problems(record: object) -> list[str]:
    """Whether the record is well formed and agrees with itself. No repository access."""
    if not isinstance(record, dict):
        return ["the record is not a JSON object"]
    found = []
    if set(record) != _KEYS:
        found.append(f"keys differ from the schema: missing {sorted(_KEYS - set(record))}, unknown {sorted(set(record) - _KEYS)}")
        return found
    if record["schema_version"] != SCHEMA_VERSION or record["kind"] != KIND:
        found.append(f"not a schema-{SCHEMA_VERSION} {KIND}")
    if record["verdict"] != "PASS":
        found.append(f"verdict is {record['verdict']!r}; only a PASS is recorded")
    units, theorems = record["units"], record["theorems"]
    if canonical_digest(units) != record["units_digest"]:
        found.append("units_digest is not the digest of the listed unit identities")
    if canonical_digest(theorems) != record["theorems_digest"]:
        found.append("theorems_digest is not the digest of the listed theorem identities")
    for label, rows, key in (("unit", units, "unit"), ("theorem", theorems, "theorem")):
        ids = [row[key] for row in rows]
        if ids != sorted(set(ids)):
            found.append(f"{label} ids are not unique and sorted")
    counts = record["counts"]
    if counts["active"] != len(theorems) or not theorems:
        found.append(f"counts.active {counts['active']} is not the {len(theorems)} listed theorem(s)")
    for axis in ("review_current", "evidence_established", "currently_verified"):
        if counts[axis] != counts["active"]:
            found.append(f"counts.{axis} {counts[axis]} is not {counts['active']}; that is not a closure")
    roots = record["roots"]
    if roots["verdict"] != "COMPLETE" or counts["roots"] != len(roots["declared"]) or counts["roots_established"] != counts["roots"]:
        found.append("the roots are not all declared and established")
    return found


def git(repo: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout.strip()


def verify(record: dict, repo: Path) -> list[str]:
    """`problems`, and the target commit resolves to the target tree in `repo`'s history.

    The history is read, never changed: a commit the clone does not hold is a failure, not
    something to fetch. A fetch here would mutate the object graph that later ancestry checks
    in the same job read, and a record naming an unmerged commit must fail, not be satisfied.
    """
    found = problems(record)
    if found:
        return found
    commit, tree = record["target"]["commit"], record["target"]["tree"]
    if git(repo, "cat-file", "-e", f"{commit}^{{commit}}")[0] != 0:
        return [f"target commit {commit} is not in this repository's history"]
    rc, resolved = git(repo, "rev-parse", f"{commit}^{{tree}}")
    if rc != 0:
        return [f"target commit {commit} does not resolve in this repository"]
    if resolved != tree:
        return [f"target commit {commit} has tree {resolved}, not the recorded {tree}"]
    return []


def identities(record: dict) -> dict[str, str | None]:
    """Every identity a record names, flat, by a name a reader can act on."""
    out: dict[str, str | None] = {
        "tree": record["target"]["tree"],
        "policy_revision": record["policy_revision"],
        "review_ledger": record["review_ledger"],
    }
    for row in record["units"]:
        out[f"unit://{row['unit']} fingerprint"] = row["fingerprint"]
    for row in record["theorems"]:
        out[f"{row['theorem']} fingerprint"] = row["fingerprint"]
        out[f"{row['theorem']} review_digest"] = row["review_digest"]
    return out


def current_identities(review: dict, tree: str | None) -> dict[str, str | None]:
    """The same names, for a tree as `review --json` derives it now."""
    return identities(
        {
            "target": {"tree": tree},
            "policy_revision": review["identities"]["policy_revision"],
            "review_ledger": review["identities"]["review_ledger"],
            "units": _unit_rows(review),
            "theorems": _theorem_rows(review),
        }
    )


def compare(record: dict, current: dict[str, str | None]) -> list[str]:
    """Each identity that differs, by name. Empty means identical; never means fresh."""
    recorded = identities(record)
    moved = []
    for name in sorted(recorded.keys() | current.keys()):
        if name not in current:
            moved.append(f"{name}: absent from the compared tree")
        elif name not in recorded:
            moved.append(f"{name}: not in the record")
        elif recorded[name] != current[name]:
            moved.append(f"{name}: {recorded[name]} -> {current[name]}")
    return moved


def path_for(commit: str) -> Path:
    return DIRECTORY / f"{commit}.json"
