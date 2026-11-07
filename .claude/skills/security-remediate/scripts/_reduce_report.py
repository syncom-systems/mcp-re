"""Markdown rendered ONLY from reduced state. Every number is a field of
`state`/`attention`; nothing is inferred, estimated or read from prose."""
from __future__ import annotations

import json
from collections import Counter

from _reduce_model import CLASS_ORDER

_PROVENANCE_FIELDS = ("auditor_version", "state_schema_version", "journal", "journal_sha256",
                      "events_reduced", "last_complete_seq", "journal_bytes_reduced",
                      "journal_bytes_dropped_incomplete", "ledger", "ledger_sha256",
                      "ledger_rows", "live", "snapshot_stable", "repo_root_for_evidence")


def _header(state: dict) -> list:
    classes = ", ".join("%s %d" % (c, state["problem_counts_by_class"][c]) for c in CLASS_ORDER)
    out = ["# Remediation run audit", "",
           "Verdict: **%s**  (%s)" % (state["verdict"].upper(), classes), "",
           "## Provenance", "",
           "| field | value |", "|---|---|"]
    out += ["| %s | `%s` |" % (k, state["source"].get(k)) for k in _PROVENANCE_FIELDS]
    return out


def _integrity(state: dict) -> list:
    check = state["ledger_check"]
    return ["", "## Integrity", "",
            "| check | value |", "|---|---|",
            "| events | %d |" % state["events"],
            "| unsequenced events | %d |" % state["unsequenced_events"],
            "| sequence gaps | %d |" % len(state["sequence_gaps"]),
            "| ledger cross-check | %s |" % ("performed" if check["checked"]
                                             else check.get("reason", "not requested")),
            "| unresolved evidence refs | %d |" % len(state["unresolved_evidence_refs"])]


def _attempts(state: dict) -> list:
    terminals = Counter(a["terminal"] or "(none)" for a in state["attempts"].values())
    out = ["", "## Attempts", "", "| terminal | attempts |", "|---|---|"]
    out += ["| %s | %d |" % (k, v) for k, v in sorted(terminals.items())]
    out.append("| **total** | **%d** |" % state["totals"]["attempts"])
    return out


def _findings(state: dict) -> list:
    t = state["totals"]
    dispositions = Counter(f["status"] for f in state["findings"].values())
    out = ["", "## Findings closed in the journal", "",
           "| disposition | findings |", "|---|---|"]
    out += ["| %s | %d |" % (k, v) for k, v in sorted(dispositions.items())]
    out += ["| **observations** | **%d** |" % t["finding_observations"],
            "| unique defect clusters | %d |" % t["unique_defect_clusters"],
            "| duplicate observations | %d |" % t["duplicate_observations"]]
    return out


def _outstanding(attention: dict) -> list:
    out = ["", "## Outstanding state (not problems)", "",
           "- unresolved work items: %d" % len(attention["UNRESOLVED_WORK"]),
           "- unresolved escalations: %d" % attention["UNRESOLVED_ESCALATIONS_TOTAL"],
           "- nonterminal attempts: %d" % len(attention["NONTERMINAL_ATTEMPTS"]),
           "", "| ruling | findings |", "|---|---|"]
    out += ["| %s | %d |" % (k, len(v))
            for k, v in attention["UNRESOLVED_ESCALATIONS_BY_RULING"].items()]
    return out


def _problem_row(p: dict) -> str:
    subject = p.get("attempt_id") or p.get("finding_id") or p.get("event_id") or ""
    detail = json.dumps(p.get("detail"), sort_keys=True).replace("|", "\\|")
    return "| %s | %s | %s | %s | %s |" % (p["class"], p["code"], p["kind"], subject,
                                          detail[:300])


def _problems(state: dict) -> list:
    out = ["", "## Problems", ""]
    if not state["problems"]:
        return out + ["None."]
    out += ["| class | code | kind | subject | detail |", "|---|---|---|---|---|"]
    rank = {c: i for i, c in enumerate(CLASS_ORDER)}
    ordered = sorted(state["problems"], key=lambda p: (rank[p["class"]], p["code"],
                                                       json.dumps(p, sort_keys=True)))
    return out + [_problem_row(p) for p in ordered]


def render_report(state: dict, attention: dict) -> str:
    out = (_header(state) + _integrity(state) + _attempts(state) + _findings(state)
           + _outstanding(attention) + _problems(state))
    return "\n".join(out) + "\n"
