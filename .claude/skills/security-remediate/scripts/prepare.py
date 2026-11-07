"""prepare.py — everything an evaluator reads before it starts judging, in ONE call.

(Invoked as `python3 prepare.py …`; no shebang — see reduce.py for why.)

WHY: an agent pays for its whole context on EVERY turn, so the cost of a file is
turns x context, and turns are the lever. Measured on a lane run: a senior
evaluator averaged 31 turns at ~84K context, and most of those turns were the
same opening every time — fetch the findings, `cat` the file, locate each
evidence excerpt, grep who imports / constructs / subclasses each symbol, find
the test module and the BUILD target. None of that is judgment. This emits all
of it at once so the evaluator's turns go to the questions only it can answer.

What it prints, in order:
  1. the findings (ledger x audit packet, the `file_findings.collect` join)
  2. where each finding's evidence excerpt sits in the CURRENT source — found at
     a line, ambiguous, or absent (an absent anchor is a `superseded` candidate,
     never a verdict: the excerpt may have been paraphrased by the reviewer)
  3. the owning BUILD.bazel and candidate test modules
  4. a usage map for every top-level symbol the file defines: production
     import / construct / subclass / reference counts, test counts, and the
     first --max-sites production sites
  5. the whole source, line-numbered

The usage map is an INSTRUMENT with a stated reach: tracked files that import
the name from this file's package, read through the AST. It cannot see a
string-keyed factory, a DI registration by name, getattr, `import pkg` followed
by attribute access, or an untracked file; Rust sites are text matches only. Every section says when it was truncated, so a
cut-off list is never read as a complete one — grep further when it matters.

Usage:
  prepare.py --ledger <ledger.jsonl> --packets <dir> --file <repo-relative path>
             [--max-sites 20] [--max-symbols 25] [--max-lines 2000] [--max-note 1500]
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _prepare_anchors import locate  # noqa: E402,F401 — the tests import it from here
from _prepare_report import (  # noqa: E402
    anchors_section, build_section, findings_section, header, source_section, usage_section)
from _prepare_symbols import defined_symbols  # noqa: E402,F401 — the tests import it from here
from _prepare_tests import test_candidates  # noqa: E402,F401 — the tests import it from here
from file_findings import collect  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--packets", default=None)
    ap.add_argument("--file", required=True)
    ap.add_argument("--max-sites", type=int, default=20)
    ap.add_argument("--max-symbols", type=int, default=25)
    ap.add_argument("--max-lines", type=int, default=2000)
    ap.add_argument("--max-note", type=int, default=1500)
    a = ap.parse_args()

    if not os.path.exists(a.file):
        print("prepare: %s does not exist in this tree — every finding on it is a "
              "`superseded` candidate" % a.file)
        return 2
    src = open(a.file, encoding="utf-8", errors="replace").read()
    lines = src.splitlines()
    joined = collect(a.ledger, a.file, a.packets)
    findings = joined["findings"]
    out = header(a.file, joined)
    out += findings_section(findings, a.max_note)
    out += anchors_section(findings, lines)
    out += build_section(a.file, src)
    out += usage_section(a, src, findings)
    out += source_section(a.file, lines, a.max_lines)
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
