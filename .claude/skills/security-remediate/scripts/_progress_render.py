"""`render`: the human view of the journal."""
from __future__ import annotations

from _progress_journal import load


def short(p: str, keep: int = 3) -> str:
    parts = (p or "").split("/")
    return "/".join(parts[-keep:]) if len(parts) > keep else (p or "")


def _line(r: dict) -> str:
    if r.get("event") == "close":
        return "%s  CLOSE  %-16s %-10s %s" % (r["ts"], r.get("status"), r.get("id"), short(r["file"]))
    c = r.get("counts", {}) or {}
    return "%s  %-26s %-8s %-58s %s" % (
        r["ts"], r.get("role", ""), r.get("event", ""), short(r.get("file", "")),
        " ".join("%s=%s" % kv for kv in sorted(c.items())))


def cmd_render(a) -> int:
    for r in load(a.log):
        print(_line(r))
    return 0
