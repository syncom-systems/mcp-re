# SPDX-License-Identifier: Apache-2.0
"""One file's gazelle diff: the targets it proposes and the dep edges it would insert."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from _bazel_gazelle.config import (
    ATTR_OPEN_RE,
    FLAVOR_PLAIN,
    LABEL_TOKEN_RE,
    NAME_RE,
    NEW_TARGET_RE,
)

Lines = list[tuple[str, str]]


def _removed_labels(lines: Lines) -> Counter:
    """How often each label is removed, so a reorder can cancel its re-insertion."""
    matches = (LABEL_TOKEN_RE.match(c) for s, c in lines if s == "-")
    return Counter(m.group(1) for m in matches if m)


def _consume_new_target(lines: Lines, start: int) -> tuple[str, int]:
    """The proposed target's name and the index after its `+` run from `nt_rust_X(` to `)`."""
    name = "<unnamed>"
    j = start + 1
    while j < len(lines) and lines[j][0] == "+":
        m = NAME_RE.match(lines[j][1])
        if m:
            name = m.group(1)
        if lines[j][1] == ")":
            break
        j += 1
    return name, j + 1


def _added_attribute_depth(depth: int, sign: str, content: str) -> int | None:
    """The new depth of wholly-added `attr = [ … ]` blocks (representation rewrites) when
    this line belongs to one, else None."""
    if sign == "+" and ATTR_OPEN_RE.match(content):
        return depth + 1
    if depth == 0:
        return None
    if sign == "+" and content == "],":
        return depth - 1
    return depth


def _inserted_edge(content: str, removed: Counter) -> str | None:
    """The label a `+` line inserts into an existing list, unless it is managed.

    `# keep` labels and flavor-plain forms are managed; a label whose removal appears
    elsewhere in the diff is a reorder and cancels it.
    """
    if "# keep" in content:
        return None
    m = LABEL_TOKEN_RE.match(content)
    if not m:
        return None
    label = m.group(1)
    if removed.get(label, 0) > 0:
        removed[label] -= 1
        return None
    return None if label.rsplit(":", 1)[-1] in FLAVOR_PLAIN else label


@dataclass
class _Scan:
    """What one pass over a file's diff has found so far."""

    removed: Counter
    names: list[str] = field(default_factory=list)
    inserted: list[str] = field(default_factory=list)
    depth: int = 0

    def note_edge(self, content: str) -> None:
        edge = _inserted_edge(content, self.removed)
        if edge:
            self.inserted.append(edge)

    def step(self, lines: Lines, i: int) -> int:
        """Consume the line at `i` (and a new target's whole block); the next index."""
        sign, content = lines[i]
        if sign == "+" and NEW_TARGET_RE.match(content):
            name, after = _consume_new_target(lines, i)
            self.names.append(name)
            return after
        in_block = _added_attribute_depth(self.depth, sign, content)
        if in_block is not None:
            self.depth = in_block
        elif sign == "+":
            self.note_edge(content)
        return i + 1


def analyze_file(lines: Lines) -> tuple[list[str], list[str]]:
    """Return (new_target_names, inserted_edge_labels) for one file's diff.

    - new_target_names: gazelle-proposed NEW targets (run of `+` from
      `nt_rust_X(` to `)`).
    - inserted_edge_labels: `+` label lines INSERTED into a list whose opener is
      a context line (an existing, gazelle-mergeable deps list) — i.e. a genuine
      missing edge. Labels inside a whole added attribute block (`+deps = [` … `+]`,
      a representation/merge-conflict rewrite of an unreadable `all_crate_deps()`/
      variable/glob form) are skipped, as are `# keep` labels and flavor-plain
      forms. Removed labels of the same value cancel (reordering).
    """
    scan = _Scan(_removed_labels(lines))
    i = 0
    while i < len(lines):
        i = scan.step(lines, i)
    return scan.names, scan.inserted
