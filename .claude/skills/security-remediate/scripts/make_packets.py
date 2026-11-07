"""make_packets.py — per-file audit packets from one or more rounds' findings.json.

`file_findings.py` joins the ledger (disposition truth) to a per-file packet
(finding content). Review rounds emit one flat findings list; this regroups it by
file and maps each finding's content fields onto the packet vocabulary, so every
round lands in the same shape whatever its lens prompt called the fields.

Usage:
  make_packets.py --out <dir> <findings.json> [<findings.json> ...]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict

# packet field <- the first finding field present, in this order
FIELD_MAP = {
    "claim": ("claim", "detail", "description"),
    "impact": ("impact", "why_it_matters"),
    "remediation": ("remediation", "suggested_fix", "recommendation"),
    "evidence": ("evidence", "excerpt"),
    "confidence": ("confidence",),
    "reported_by": ("lens", "reported_by"),
    "needs_outside_packet": ("needs_outside_packet",),
    "round_id": ("id",),
}


def _first(f: dict, keys: tuple[str, ...]):
    for k in keys:
        if f.get(k) not in (None, ""):
            return f[k]
    return None


def _findings_of(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return doc if isinstance(doc, list) else doc.get("findings", [])


def _file_of(finding: dict) -> str:
    return (finding.get("file") or finding.get("location") or "").split(":")[0].strip()


def _row_of(finding: dict) -> dict:
    row = {"title": finding.get("title"), "line": finding.get("line"),
           "severity": finding.get("severity"),
           "provisional": bool(finding.get("needs_outside_packet"))}
    for dst, src in FIELD_MAP.items():
        value = _first(finding, src)
        if value is not None:
            row[dst] = value
    return row


def packet_rows(paths: list[str]) -> dict[str, list[dict]]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for finding in (f for p in paths for f in _findings_of(p)):
        path = _file_of(finding)
        if path:
            by_file[path].append(_row_of(finding))
    return by_file


def main() -> int:
    ap = argparse.ArgumentParser(description="per-file audit packets from findings.json rounds")
    ap.add_argument("--out", required=True)
    ap.add_argument("findings", nargs="+")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    by_file = packet_rows(a.findings)
    for path, rows in sorted(by_file.items()):
        name = hashlib.sha1(path.encode()).hexdigest()[:12] + ".json"
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as fh:
            json.dump({"file": path, "findings": rows}, fh, indent=1)
    print("make_packets: %d file(s), %d finding(s) -> %s"
          % (len(by_file), sum(len(r) for r in by_file.values()), a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
