"""The argument parser: one sub-parser per `progress.py` subcommand."""
from __future__ import annotations

import argparse

from _progress_reconcile import cmd_reconcile
from _progress_render import cmd_render
from _progress_stats import cmd_stats
from _progress_watch import cmd_watch
from _progress_write import cmd_append, cmd_close


def _add_append(sub) -> None:
    ad = sub.add_parser("append")
    ad.add_argument("--log", required=True)
    ad.add_argument("--file", required=True)
    ad.add_argument("--role", required=True)
    ad.add_argument("--event", required=True,
                    help="evaluate | fix | gate | review | no-code-change | gate-failed | exhausted | regression")
    ad.add_argument("--tier", default="")
    ad.add_argument("--model", default="")
    ad.add_argument("--counts", default="", help="k=v,k=v (work, disposed, closed, escalated, applied, not_applied, exit, rejected) — a CHECKSUM over the attempt, not a delta to sum")
    ad.add_argument("--note", default="", help="bounded, human-readable; put the full reasoning in --evidence-ref")
    ad.add_argument("--attempt", default="", help="attempt id shared by every event of ONE file-processing attempt")
    ad.add_argument("--run", default="", help="run id, e.g. audit-2026-09-22")
    ad.add_argument("--epoch", default="", help="policy epoch; stats are filtered by it, never averaged across one")
    ad.add_argument("--work-ids", dest="work_ids", default="",
                    help="comma-separated ids of the work items this event created/resolved")
    ad.add_argument("--escalation-ids", dest="escalation_ids", default="",
                    help="comma-separated ids of escalations raised — WHICH ones, not how many")
    ad.add_argument("--finding-ids", dest="finding_ids", default="",
                    help="comma-separated finding ids this event covers")
    ad.add_argument("--ruling", default="", help="shared ruling id that discharges these escalations")
    ad.add_argument("--reject-causes", dest="reject_causes", default="",
                    help="review only: comma-separated causes, one per rejected item — "
                         "scope | evidence | wrong-fix | anchor | other")
    ad.add_argument("--evidence-ref", dest="evidence_ref", default="",
                    help="path to the immutable artifact holding the full reasoning")
    ad.set_defaults(fn=cmd_append)


def _add_close(sub) -> None:
    cl = sub.add_parser("close")
    cl.add_argument("--log", required=True)
    cl.add_argument("--file", required=True)
    cl.add_argument("--id", required=True)
    cl.add_argument("--status", required=True)
    cl.add_argument("--severity", default="")
    cl.add_argument("--reason", required=True)
    cl.add_argument("--role", default="evaluator")
    cl.add_argument("--tier", default="")
    cl.add_argument("--model", default="")
    cl.add_argument("--attempt", default="", help="the attempt this closure belongs to")
    cl.add_argument("--run", default="")
    cl.add_argument("--epoch", default="")
    cl.add_argument("--duplicate-of", dest="duplicate_of", default="",
                    help="finding id this one duplicates — a FIELD, not a sentence in --reason")
    cl.add_argument("--cluster", default="", help="cluster id: several observations of ONE defect")
    cl.add_argument("--ruling", default="", help="shared ruling id discharging this escalation")
    cl.add_argument("--evidence-ref", dest="evidence_ref", default="",
                    help="path to the artifact holding the full adjudication")
    cl.set_defaults(fn=cmd_close)


def _add_reading(sub) -> None:
    rc = sub.add_parser("reconcile")
    rc.add_argument("--log", required=True)
    rc.add_argument("--files", default="", help="comma-separated files the batch was supposed to cover")
    rc.set_defaults(fn=cmd_reconcile)

    st = sub.add_parser("stats")
    st.add_argument("--log", required=True)
    st.add_argument("--epoch", default="", help="only events from this policy epoch")
    st.add_argument("--run", default="", help="only events from this run id")
    st.set_defaults(fn=cmd_stats)

    wt = sub.add_parser("watch")
    wt.add_argument("--zero-work-streak", type=int, default=5)
    wt.add_argument("--close-rate", type=float, default=0.5)
    wt.add_argument("--anchor-misses", type=int, default=2)
    wt.set_defaults(fn=cmd_watch)

    rn = sub.add_parser("render")
    rn.add_argument("--log", required=True)
    rn.set_defaults(fn=cmd_render)


def build_parser(description: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=description)
    sub = ap.add_subparsers(dest="cmd", required=True)
    _add_append(sub)
    _add_close(sub)
    _add_reading(sub)
    return ap
