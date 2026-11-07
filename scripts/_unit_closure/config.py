"""Paths, vocabulary and register schema of the unit-closure gate."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTER_REL = "config/unit-closure-exclusions.toml"
REGISTER = REPO / REGISTER_REL

# Module resolution is IMPORTED, not re-written: `_module_tree` is the one owner of which
# file a `mod` names, and a second copy would be a second opinion about what a module is.
import _ratchet

#: A Rust item declared at the start of a line, after any visibility and any of the
#: modifiers that may precede one. `use` and `mod` are absent on purpose: a file whose whole
#: body is those two is a namespace, which is what UC-2's item test exists to recognise.
ITEM = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:default[ \t]+)?(?:unsafe[ \t]+)?"
    r"(?:async[ \t]+)?(?:const[ \t]+)?(?:extern[ \t]+(?:\"[^\"]*\"[ \t]+)?)?"
    r"(?:fn|struct|enum|trait|impl|const|static|type|union|macro_rules!)\b",
    re.M,
)

#: The three dispositions. See the gate's docstring: a completed census whose disposition is
#: "attach it" must stay distinguishable from one nobody has performed.
STATUSES = {"unreviewed", "reviewed-attached", "reviewed-out-of-cone"}
REVIEWED = {"reviewed-attached", "reviewed-out-of-cone"}

#: Anything else in an `[[exclusion]]` table is a typo or a stale field name, and both fail.
#: `rule` is here rather than in a comment because it is DERIVED: a reader needs to know why
#: a path is registered, and a derived sentence nothing checks is exactly the kind of prose
#: that rots into a claim about a tree that has moved. As a field the gate re-derives it and
#: refuses a mismatch, so it can be read as a fact.
ENTRY_FIELDS = {"path", "rule", "baseline_sha", "status", "reason", "review_ref"}

#: Every permitted move either preserves or increases what is known. None returns an entry
#: to "nobody has investigated this", because that would tell the next reader to redo the
#: work. A reviewed entry may change its mind in either direction: a re-review that finds a
#: home for an out-of-cone file, or one that decides an attachment was wrong, are both
#: reviews.
PERMITTED_TRANSITIONS = {
    ("unreviewed", "unreviewed"),
    ("unreviewed", "reviewed-attached"),
    ("unreviewed", "reviewed-out-of-cone"),
    ("reviewed-attached", "reviewed-attached"),
    ("reviewed-attached", "reviewed-out-of-cone"),
    ("reviewed-out-of-cone", "reviewed-out-of-cone"),
    ("reviewed-out-of-cone", "reviewed-attached"),
}

#: The register's shape. `_ratchet` checks it; `validate_register` adds the one field rule
#: that is this gate's own.
SCHEMA = _ratchet.Schema(
    table="exclusion",
    key="path",
    required=frozenset({"path", "rule", "baseline_sha", "status"}),
    fields=frozenset(ENTRY_FIELDS),
    statuses=tuple(sorted(STATUSES)),
    reviewed=frozenset(REVIEWED),
)


def exclusions(root: Path = REPO) -> _ratchet.Register:
    return _ratchet.Register(REGISTER_REL, SCHEMA, root)
