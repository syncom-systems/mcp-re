# SPDX-License-Identifier: Apache-2.0
"""The artifact verifiers' non-vacuity probe — r12 Ruling 38 §7.

The thumbprint relation the four public artifact verifiers ensure is written over two
UNINTERPRETED functions (`sha256_of`, `b64url_of`). An uninterpreted symbol can make a
postcondition read as a guarantee while constraining nothing — a contract stated over a
function the prover may choose freely is satisfied by any body. So the lane does not take
the verifiers' green for the connection; it asks the real prover three questions it can only
answer one way if the relation constrains:

  * the positive control, which calls `verify_artifact_binding` and ensures the relation,
    must VERIFY;
  * `probe_negative_relation_removed`, which ensures the relation without the comparison
    that establishes it, must FAIL;
  * `probe_negative_relation_contradicted`, which ensures the relation over a credential
    the binding was not checked against, must FAIL.

The probe module is compiled only by `//mcp-re-http-profile/verus_probe:nonvacuity_probe`,
which turns on the `verus_nonvacuity_probe` cfg; no library build and no unit's own run sees
it. Exactly the two negatives failing, and nothing else, is the only passing answer: a third
error means the crate itself does not verify under the probe, which is a different fault the
probe must not absorb.
"""

from __future__ import annotations

import re

from _verus_results import CrateReport

LABEL = "//mcp-re-http-profile/verus_probe:nonvacuity_probe"
SOURCE = "mcp-re-http-profile/src/artifact/nonvacuity_probe.rs"
CRATE = "mcp_re_http_profile"
MODULE = "mcp_re_http_profile::artifact::nonvacuity_probe::"
POSITIVE = frozenset({"probe_the_contract_carries_the_relation"})
NEGATIVE = frozenset({"probe_negative_relation_removed", "probe_negative_relation_contradicted"})

_LOCATION = re.compile(r"^\s*-->\s+(?P<path>[^:\s]+):(?P<line>\d+):\d+", re.M)
_ERROR = re.compile(r"^error(?:\[[A-Z0-9]+\])?: (?!aborting)", re.M)
_FN = re.compile(r"^\s*pub fn (?P<name>[a-z_0-9]+)\(", re.M)


def failing_locations(log: str) -> list[tuple[str, int]]:
    """The primary location of every prover error in `log`, in order.

    The first `-->` after an `error:` line is that error's primary span. `aborting due to …`
    is the summary, not an error of its own, and has no location.
    """
    found: list[tuple[str, int]] = []
    for error in _ERROR.finditer(log):
        location = _LOCATION.search(log, error.end())
        if location is None:
            found.append(("<no location>", 0))
            continue
        found.append((location["path"], int(location["line"])))
    return found


def owning_function(source: str, line: int) -> str | None:
    """The probe function whose specification or body holds `line` (1-based).

    A postcondition failure is reported at the `ensures` clause, which sits ABOVE the `fn`
    line in attribute-style Verus, so the owner is the first function declared at or after
    the line.
    """
    for match in _FN.finditer(source):
        declared_at = source.count("\n", 0, match.start()) + 1
        if declared_at >= line:
            return match["name"]
    return None


def _report_refusal(mine: list[CrateReport], status: int | None) -> str | None:
    """Why the one report for the probe crate cannot be judged, or None when it can."""
    if len(mine) != 1:
        return f"expected one report for {CRATE}, found {len(mine)}"
    report = mine[0]
    if not report.entire_crate:
        return "the probe run verified only part of the crate"
    absent = sorted({MODULE + name for name in POSITIVE | NEGATIVE} - report.symbols)
    if absent:
        return (
            f"probe function(s) absent from the report: {', '.join(absent)} — the probe module "
            "was not compiled, so nothing was asked"
        )
    if status == 0 or report.success:
        return (
            "the probe run SUCCEEDED: a postcondition over the thumbprint relation was proved "
            "for a body that does not establish it, so the relation constrains nothing"
        )
    return None


def _failing_owners(log: str, source: str) -> tuple[list[str], str | None]:
    """The probe function owning each failing location in `log`, or why one has no owner."""
    owners: list[str] = []
    for path, line in failing_locations(log):
        if path != SOURCE:
            return owners, f"an error outside the probe module ({path}:{line}): the crate itself does not verify"
        owner = owning_function(source, line)
        if owner is None:
            return owners, f"an error at {path}:{line} belongs to no probe function"
        owners.append(owner)
    return owners, None


def _owners_refusal(report: CrateReport, owners: list[str]) -> str | None:
    """Why the failing owners are not exactly the negatives, or None when they are."""
    if report.errors != len(owners):
        return f"the report counts {report.errors} error(s), the log locates {len(owners)}"
    if set(owners) & POSITIVE:
        return "the positive control failed: the public contract does not carry the relation"
    if sorted(owners) != sorted(NEGATIVE):
        return f"expected exactly {sorted(NEGATIVE)} to fail, got {sorted(owners)}"
    return None


def evaluate(reports: list[CrateReport], log: str, status: int | None, source: str) -> tuple[bool, str]:
    """Did the prover refuse exactly the two negatives and verify the positive control?"""
    mine = [r for r in reports if CRATE in r.crates]
    refusal = _report_refusal(mine, status)
    if refusal:
        return False, refusal
    owners, refusal = _failing_owners(log, source)
    refusal = refusal or _owners_refusal(mine[0], owners)
    if refusal:
        return False, refusal
    return True, (
        f"{len(NEGATIVE)} negative probe(s) refused, positive control verified "
        f"({mine[0].verified} verified)"
    )
