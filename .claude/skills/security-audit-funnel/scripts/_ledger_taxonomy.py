"""The disposition taxonomy: which statuses are open, closed or refused, and why a row is not validly closed."""
from __future__ import annotations

import os
import re
import tomllib

SUPPRESS = {"fixed", "false-positive", "superseded", "positive-control", "informational",
            "premise", "constraint"}
# Statuses kept OFF the remediation worklist. `informational` = an info-severity
# finding: captured durably and emitted in the per-run info digest issue, but
# NOT worked by the file-by-file loop (ADR-SEC-023 funnel policy: critical→low
# are all dealt with; info is "might look into, or not").

OPEN_STATUSES = {"open", "escalated", "needs-senior-eval", "regression"}
CLOSED_STATUSES = {"fixed", "false-positive", "premise", "constraint", "superseded",
                   "duplicate", "positive-control", "informational", "handled-prior-round"}
# Not dispositions. "Real, and we decided to live with it" closes nothing: the defect
# is still there, and a ledger that counts it closed reports a zero that measures nothing.
REFUSED_STATUSES = {"accepted-risk", "wontfix"}
ASSUMPTIONS_TOML = "verification/policy/assumptions.toml"
_ASM = re.compile(r"^ASM-\d{4}$")
_OWNER_RULING = re.compile(r"^Ruling \d+(\.\d+)?\b")


def registered_assumptions(path=ASSUMPTIONS_TOML):
    """The ASM ids registered in `path`, or None when the registry is not present."""
    if not path or not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return {a["id"] for a in tomllib.load(fh).get("assumption", [])}


def _premise_problem(e, assumptions):
    asm = str(e.get("premise", ""))
    if not _ASM.match(asm):
        return "premise names no ASM id (`premise` = %r)" % asm
    if assumptions is not None and asm not in assumptions:
        return "premise %s is not registered in %s" % (asm, ASSUMPTIONS_TOML)
    return None


def _constraint_problem(e):
    if _OWNER_RULING.match(str(e.get("owner_ruling", ""))):
        return None
    return "constraint names no owner ruling (`owner_ruling` = %r)" % e.get("owner_ruling")


def closure_problem(e, assumptions):
    """Why `e` is not a valid disposition, or None. `assumptions` None skips the ASM lookup."""
    st = e.get("status")
    if st in REFUSED_STATUSES:
        return "status %r is not a disposition: fix it, disprove it, or leave it open" % st
    if st not in OPEN_STATUSES | CLOSED_STATUSES:
        return "status %r is not in the taxonomy" % st
    if st == "premise":
        return _premise_problem(e, assumptions)
    if st == "constraint":
        return _constraint_problem(e)
    return None


def is_open(e, assumptions):
    """Open unless validly closed: a row the taxonomy cannot close counts as open."""
    return e.get("status") in OPEN_STATUSES or closure_problem(e, assumptions) is not None
