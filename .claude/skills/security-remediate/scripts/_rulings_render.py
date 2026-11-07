"""The ruling queue as the markdown a human answers between ticks."""
from __future__ import annotations

from _rulings_queue import SEV_NAME, SIGN, Queue, path_of, rank, worst

_ANSWER = [
    "Answer a decision by setting its finding's ledger status, e.g.\n",
    "```bash",
    "python3 .claude/skills/security-remediate/scripts/ledger.py set <ledger> \\",
    "  --id <id> --status open --method review-adjudicated --note \"RULED: <the decision>\"",
    "```",
    "`open` returns it to the worklist with the ruling recorded; `constraint` "
    "with `--owner-ruling \"Ruling N\"` records a demonstrated architectural "
    "constraint you accepted. There is no accepted-risk: a real defect is fixed.\n",
]


def decision_count(queue: Queue, blocked_on: dict[str, str]) -> int:
    """One per ruling id, plus one per file the evaluator gave a single decision, else one
    per escalated finding."""
    per_file = sum(1 if blocked_on.get(f) else len(rs) for f, rs in queue.by_file.items())
    return len(queue.decisions) + per_file


def render(queue: Queue, blocked_on: dict[str, str]) -> str:
    lines = _header(queue, decision_count(queue, blocked_on))
    for title, keys in (("Decisions", queue.decisions),
                        ("Ratifications — one surviving text, owner-ratified surface",
                         queue.signature)):
        lines += _ruling_section(title, keys, queue)
    if queue.by_file:
        lines.append("\n## Escalations with no ruling id, by file\n")
    for f in sorted(queue.by_file, key=lambda f: worst(queue.by_file[f])):
        lines += _file_section(f, queue, blocked_on)
    return "\n".join(lines) + "\n"


def _header(queue: Queue, n_decisions: int) -> list[str]:
    return ["# Ruling queue — security-remediate\n",
            "%d escalated finding(s) collapse to **%d decision(s)** and **%d ratification(s)** "
            "over %d file(s). Each entry below blocks the findings folded under it; the lane "
            "is not waiting on you — it records these and keeps working other files.\n"
            % (len(queue.escalated), n_decisions, len(queue.signature), len(queue.files)),
            *_ANSWER]


def _ruling_section(title: str, keys: list[str], queue: Queue) -> list[str]:
    lines = ["\n## %s\n" % title] if keys else []
    for key in keys:
        lines += _ruling_entry(key, queue)
    return lines


def _ruling_entry(key: str, queue: Queue) -> list[str]:
    rs = queue.by_ruling[key]
    folded = queue.folded
    paths = sorted({path_of(r) for r in rs})
    total = len(rs) + sum(len(folded.get(r["id"], [])) for r in rs)
    lines = ["\n### [%s] `%s` — %d finding(s)\n" % (SEV_NAME[worst(rs)], key, total),
             "- **files**: %s" % ", ".join("`%s`" % p for p in paths)]
    for r in sorted(rs, key=rank):
        kids = folded.get(r["id"], [])
        also = (" (+ %s)" % ", ".join("`%s`" % c["id"] for c in kids)) if kids else ""
        lines.append("- [%s] %s `%s`%s" % (str(r.get("severity", "")).upper(),
                                          r.get("title", ""), r["id"], also))
    lines.append("- **evaluator**: %s" % (rs[0].get("notes") or "(no note recorded)"))
    lines.append("- **ratified**: " if key.startswith(SIGN) else "- **decision**: ")
    return lines


def _file_section(f, queue: Queue, blocked_on: dict[str, str]) -> list[str]:
    rows = queue.by_file[f]
    decision = blocked_on.get(f)
    lines = ["\n### `%s`\n" % f]
    if decision:
        lines += ["> **THE DECISION for this file** — the evaluator that read it states every "
                  "escalation below waits on this one thing:\n>\n> %s\n"
                  % decision.replace("\n", " "),
                  "- **ruling**: \n",
                  "<details><summary>the %d finding(s) it blocks</summary>\n" % len(rows)]
    for r in sorted(rows, key=rank):
        lines += _file_finding(r, queue, bool(decision))
    if decision:
        lines.append("\n</details>\n")
    return lines


def _file_finding(r: dict, queue: Queue, has_decision: bool) -> list[str]:
    kids = queue.folded.get(r["id"], [])
    lines = ["\n#### [%s] %s  `%s`\n" % (str(r.get("severity", "")).upper(),
                                        r.get("title", ""), r["id"]),
             "- **evaluator's finding**: %s" % (r.get("notes") or "(no note recorded)")]
    if kids:
        lines.append("- **also waiting on this decision** (%d): %s"
                     % (len(kids), ", ".join("`%s`" % k["id"] for k in kids)))
    lines.append("" if has_decision else "- **decision**: ")
    return lines
