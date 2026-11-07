"""The argument parser: one sub-parser per `ledger.py` subcommand."""
from __future__ import annotations

import argparse

from _ledger_commands import cmd_check, cmd_fingerprint, cmd_set, cmd_stats
from _ledger_ingest import cmd_ingest, cmd_reconcile
from _ledger_taxonomy import ASSUMPTIONS_TOML


def _add_set(sub) -> None:
    st = sub.add_parser("set")
    st.add_argument("ledger")
    st.add_argument("--id", required=True)
    st.add_argument("--status")
    st.add_argument("--method")
    st.add_argument("--issue", type=int)
    st.add_argument("--pr", type=int)
    st.add_argument("--note")
    st.add_argument("--duplicate-of", dest="duplicate_of",
                    help="finding id this one duplicates (structural, not prose)")
    st.add_argument("--cluster", help="cluster id: several observations of ONE defect")
    st.add_argument("--ruling", help="shared ruling id that discharges this escalation")
    st.add_argument("--premise", help="status=premise: the registered ASM id it states")
    st.add_argument("--owner-ruling", dest="owner_ruling",
                    help='status=constraint: the owner ruling that accepted it ("Ruling 22.1")')
    st.add_argument("--assumptions", default=ASSUMPTIONS_TOML)
    st.set_defaults(fn=cmd_set)


def _add_reading(sub) -> None:
    fp = sub.add_parser("fingerprint")
    fp.add_argument("--file", required=True)
    fp.add_argument("--title", required=True)
    fp.set_defaults(fn=cmd_fingerprint)

    ig = sub.add_parser("ingest")
    ig.add_argument("ledger")
    ig.add_argument("prerun")
    ig.add_argument("--round", required=True)
    ig.add_argument("--status")
    ig.add_argument("--method")
    ig.set_defaults(fn=cmd_ingest)

    rc = sub.add_parser("reconcile")
    rc.add_argument("ledger")
    rc.add_argument("prerun")
    rc.set_defaults(fn=cmd_reconcile)


def _add_audit(sub) -> None:
    st2 = sub.add_parser("stats")
    st2.add_argument("ledger")
    st2.add_argument("--assumptions", default=ASSUMPTIONS_TOML)
    st2.set_defaults(fn=cmd_stats)

    ck = sub.add_parser("check")
    ck.add_argument("ledger")
    ck.add_argument("--assumptions", default=ASSUMPTIONS_TOML)
    ck.set_defaults(fn=cmd_check)


def build_parser(description: str | None) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(required=True)
    _add_reading(sub)
    _add_set(sub)
    _add_audit(sub)
    return p
