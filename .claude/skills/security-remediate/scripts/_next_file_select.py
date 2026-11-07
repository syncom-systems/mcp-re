"""Choosing the next file: the worklist, its order, and the batch entries."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass

from _next_file_graph import load_deps, related_of, topo_order
from _next_file_tier import by_severity, eval_tier, gate_tier, max_sev
from file_findings import ACTIONABLE

# Statuses that block a file but cannot be auto-progressed (need a human).
BLOCKED = {"escalated", "exhausted"}


@dataclass(frozen=True)
class Scope:
    """What narrows or sequences the worklist: live rounds, and an explicit campaign order."""
    rounds: set[str] | None = None
    order_path: str | None = None


def _load_ledger(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def _latest_by_fingerprint(records: list[dict]) -> list[dict]:
    """A ledger is append-only; keep the last record per fingerprint."""
    latest: dict[str, dict] = {}
    for r in records:
        fp = r.get("id") or r.get("fingerprint") or f"{r.get('file')}|{r.get('title')}"
        latest[fp] = r
    return list(latest.values())


def _campaign_order(path: str | None) -> list[str]:
    """Paths in campaign order: a JSON list of paths or of `{"file": path}` rows."""
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return [row["file"] if isinstance(row, dict) else row for row in doc]


def _worklist(records: list[dict]) -> tuple[dict, dict]:
    """Actionable findings by file, and the count of findings only a human can move."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    blocked = {"escalated": 0, "exhausted": 0}
    for r in records:
        status = str(r.get("status", "open")).lower()
        # Ledger keys findings by basename in `file`; `path` (full relpath) is
        # preferred for the worklist + leaf-first ordering when present.
        key = r.get("path") or r.get("file")
        if status in ACTIONABLE:
            by_file[key].append(r)
        elif status in BLOCKED:
            blocked[status] += 1
    return by_file, blocked


def _order(by_file: dict, deps: dict, order_path: str | None) -> list[str]:
    open_files = list(by_file.keys())

    def priority(f: str):
        fs = by_file.get(f, [])
        return (-max_sev(fs), -len(fs), f)

    campaign = [f for f in _campaign_order(order_path) if f in by_file]
    if campaign:
        # An explicit campaign order is the owner's sequencing and outranks the
        # derived one; files it does not list follow in the derived order.
        rest = [f for f in open_files if f not in set(campaign)]
        tail = topo_order(rest, deps, priority) if deps else sorted(rest, key=priority)
        return campaign + [f for f in tail if f in by_file]
    if deps:
        return [f for f in topo_order(open_files, deps, priority) if f in by_file]
    # No dep graph: highest max-severity first, then most findings, then path.
    return sorted(open_files, key=priority)


def _batch_entry(f: str, findings: list[dict], graph: tuple[dict, dict, dict]) -> dict:
    deps, rdeps, importers = graph
    n_i = importers.get(f, 0)
    fs = by_severity(findings)
    tier, why = eval_tier(fs)
    return {
        "file": f,
        "related": related_of(f, deps, rdeps),
        "findings": fs,
        "n_findings": len(fs),
        "importers": n_i,
        "gate_tier": gate_tier(n_i),
        "eval_tier": tier,
        "eval_tier_reason": why,
    }


def _exhausted(blocked: dict) -> dict:
    return {"exhausted": True, "file": None, "related": [], "findings": [],
            "blocked": blocked, "remaining_open_files": 0}


def select(ledger_path: str, deps_path: str | None, top: int = 1,
           scope: Scope | None = None) -> dict:
    scope = scope or Scope()
    records = _latest_by_fingerprint(_load_ledger(ledger_path))
    if scope.rounds:
        # Only findings a live round reported; a row last seen in a superseded
        # round describes a tree that no longer exists.
        records = [r for r in records if scope.rounds & set(r.get("rounds") or [r.get("last_seen")])]
    by_file, blocked = _worklist(records)
    graph = load_deps(deps_path)
    if not by_file:
        return _exhausted(blocked)

    deps, rdeps, importers = graph
    order = _order(by_file, deps, scope.order_path)
    chosen = order[0]
    # A batch of the next `top` files, so a driver can fan out read-only
    # evaluation ahead of the single writer without re-querying per file. The
    # order is the same one the single-file answer follows.
    batch = [_batch_entry(f, by_file[f], graph) for f in order[:max(1, top)]]
    related = related_of(chosen, deps, rdeps)
    n_imp = importers.get(chosen, len(related))
    return {
        "exhausted": False,
        "file": chosen,
        "related": related,
        "findings": by_severity(by_file[chosen]),
        "blocked": blocked,
        "remaining_open_files": len(by_file),
        "importers": n_imp,
        "gate_tier": gate_tier(n_imp),
        "eval_tier": batch[0]["eval_tier"] if batch else "senior",
        "eval_tier_reason": batch[0]["eval_tier_reason"] if batch else "",
        "batch": batch,
    }
