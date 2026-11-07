"""Where a finding's evidence excerpt sits in the current source."""
from __future__ import annotations

import re

_LINE_PREFIX = re.compile(r"^\s*(?:L?\d+\s*[:|]\s?|\d+\t)")


def _anchor_lines(evidence: str | None) -> list[str]:
    """The excerpt's significant lines, with any `123:` / `L123 |` prefix removed.

    Reviewers quote with line-number prefixes and elide with `...`; neither is in
    the source. Lines shorter than 8 characters (`}`, `)`, `else:`) match
    everywhere and anchor nothing, so they are dropped.
    """
    out = []
    for raw in (evidence or "").splitlines():
        line = _LINE_PREFIX.sub("", raw).strip()
        if len(line) < 8 or line.startswith(("...", "…")):
            continue
        out.append(line)
    return out


def _partial(anchors: list[str], stripped: list[str], rest_present: int) -> dict | None:
    """The first excerpt line is absent: any later line still anchors, as `partial`."""
    later = [(a, [i + 1 for i, s in enumerate(stripped) if a in s]) for a in anchors[1:]]
    later = [(a, h) for a, h in later if h]
    if not later:
        return None
    return {"state": "partial", "lines": later[0][1][:5],
            "detail": "first excerpt line absent; %d/%d later lines present"
                      % (rest_present, len(anchors) - 1)}


def locate(evidence: str | None, src_lines: list[str]) -> dict:
    """Where the excerpt sits now. Keyed on the FIRST significant line, then
    checked for the rest — a partial hit is reported as partial, not as found."""
    anchors = _anchor_lines(evidence)
    if not anchors:
        return {"state": "no-anchor", "detail": "the packet carries no usable excerpt"}
    stripped = [s.strip() for s in src_lines]
    first = anchors[0]
    hits = [i + 1 for i, s in enumerate(stripped) if first in s]
    rest_present = sum(1 for a in anchors[1:] if any(a in s for s in stripped))
    rest = len(anchors) - 1
    if not hits:
        # The first line may be the paraphrased one; any later line still anchors.
        partial = _partial(anchors, stripped, rest_present)
        if partial:
            return partial
        return {"state": "absent",
                "detail": "no excerpt line is present — `superseded` CANDIDATE; confirm "
                          "the code is really gone, not paraphrased by the reviewer"}
    state = "found" if len(hits) == 1 else "ambiguous"
    detail = "" if not rest else "%d/%d further excerpt lines present" % (rest_present, rest)
    return {"state": state, "lines": hits[:5], "detail": detail}
