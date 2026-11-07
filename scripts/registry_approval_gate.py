#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Registry approval gate — no policy registry may carry a mutable approval string.

WHAT THIS PROVES, exactly: no file under `verification/policy/` declares a key that
represents review or approval STATE, no record under `verification/reviews/` carries one
either, and every such record names what it is about — the fingerprint an approval
approves, or the tree a measurement was taken against.

WHAT IT DOES NOT PROVE: that any approval is genuine, that a reviewer read anything, or
that the fingerprint a record names was ever computed honestly. It proves only that
approval is expressed as evidence ABOUT a fingerprint and not as a bit on the object
approved.

WHY IT MATTERS (ADR-MCPRE-059 §14.7). A stored `review = "approved"` answers the wrong
question: it does not say WHICH proposition was approved, so it survives every edit to the
proposition. It also makes a self-approving change a single-file operation, and — where the
record is itself fingerprinted — it is either inside its own fingerprint, so flipping it
dirties the evidence it approves, or it is silently excluded, so the fingerprint means
"some subset". Both are incoherent.

The theorem loader already rejects these keys inside `theorems.toml`. This gate is the
repository-wide statement of the same rule: it covers the sibling registries, catches a key
smuggled into a nested table the loader's flat key check would not reach, and keeps working
if a fourth registry is added tomorrow.

Run:  python3 scripts/registry_approval_gate.py
      python3 scripts/registry_approval_gate.py --selftest
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))
import _registries  # noqa: E402

REVIEWS_DIR = REPO / "verification" / "reviews"

#: Keys that express review/approval STATE. Deliberately not "any key containing the word
#: review": `review_requirement` (who must review) and `reviewed_fingerprint` (which
#: fingerprint was reviewed) are both legitimate and both must keep working, so the set is
#: enumerated rather than pattern-matched.
FORBIDDEN = {
    "approved",
    "approval",
    "review_status",
    "reviewed_by_status",
    "signed_off",
    "sign_off",
    "verdict",
    "audited",
    "attested",
    "clean",
    "status",
    "state",
}

#: Keys that LOOK like the forbidden ones and are the mechanism itself. Listed so a future
#: reader does not "tighten" the gate into refusing the thing it exists to require.
PERMITTED = {"review_requirement", "reviewed_fingerprint", "reviewer", "subject", "axis"}

#: The one exemption, named rather than implied, because a gate's exemption is part of what
#: it measured. `toolchains.lock.toml` uses `state = "resolved" | "unresolved"` to say
#: whether a TOOL'S IDENTITY is pinned — a fact about the lock file, not a review verdict
#: about code — and `_toolchain_lock.load_toolchains` already validates it as a closed enum and
#: refuses anything else. Every other file, including any future registry, is covered.
EXEMPT_KEYS: dict[str, set[str]] = {"toolchains.lock.toml": {"state"}}


def _dict_offences(value: dict, path: str, exempt: set[str]) -> list[str]:
    found: list[str] = []
    for key, sub in value.items():
        if key in PERMITTED or key in exempt:
            continue
        where = f"{path}.{key}" if path else str(key)
        if key in FORBIDDEN:
            found.append(where)
        found.extend(offending_keys(sub, where, exempt))
    return found


def offending_keys(value, path: str = "", exempt: set[str] | None = None) -> list[str]:
    """Every forbidden key in a parsed document, as dotted paths."""
    exempt = exempt or set()
    if isinstance(value, dict):
        return _dict_offences(value, path, exempt)
    if isinstance(value, list):
        return [
            found
            for index, item in enumerate(value)
            for found in offending_keys(item, f"{path}[{index}]", exempt)
        ]
    return []


def _measurement_defects(doc: dict, where: Path) -> list[str]:
    defects = []
    if "re_derived_against" not in doc:
        defects.append(
            f"{where}: a measurement record must name the tree it measured "
            f"(`re_derived_against`)."
        )
    if "reviewed_fingerprint" in doc:
        defects.append(
            f"{where}: a measurement record carries a `reviewed_fingerprint`. "
            f"Measuring is not approving; one of the two facts is misdeclared."
        )
    return defects


def naming_defects(doc: dict, path: Path) -> list[str]:
    """Every record under `verification/reviews/` must name what it is about.

    Two kinds of document live here and they name different things. An APPROVAL record —
    the default, and what every `specification/THM-NNNN.json` is — names the
    `reviewed_fingerprint` it approves; without it the approval is about nothing in
    particular and survives every edit to the proposition. A MEASUREMENT record names the
    tree it was taken against, and must NOT carry a `reviewed_fingerprint`, because a
    measurement approves nothing at all.

    The kind is declared, not inferred from the filename: `record_kind = "measurement"`.
    Inferring it would let a document acquire the weaker obligation by being renamed, and
    the obligations are the whole point of the distinction.
    """
    kind = doc.get("record_kind", "approval")
    where = path.relative_to(REPO)
    if kind == "measurement":
        return _measurement_defects(doc, where)
    if kind != "approval":
        return [f"{where}: unknown `record_kind` {kind!r}. Expected approval or measurement."]
    if "reviewed_fingerprint" in doc:
        return []
    return [
        f"{where}: no `reviewed_fingerprint`. A review that does not name what it "
        f"reviewed approves nothing in particular."
    ]


def _policy_failures(path: Path) -> list[str]:
    """The stored approval/status fields one policy registry carries."""
    try:
        doc = _registries.read(path, path.relative_to(REPO).as_posix())
    except _registries.ManifestError as exc:
        return [str(exc)]
    exempt = EXEMPT_KEYS.get(path.name, set())
    return [
        f"{path.relative_to(REPO)}: `{key}` is a stored approval/status field. "
        f"An approval is evidence ABOUT a fingerprint (ADR-MCPRE-059 §14.7); "
        f"record it in verification/reviews/ keyed by reviewed_fingerprint."
        for key in offending_keys(doc, exempt=exempt)
    ]


def _review_failures(path: Path) -> list[str]:
    """The stored approval bits, and the naming defects, of one review record."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path.relative_to(REPO)}: unparsable: {exc}"]
    failures = [
        f"{path.relative_to(REPO)}: `{key}` is a stored approval bit. A review "
        f"record says which fingerprint was reviewed and nothing else."
        for key in offending_keys(doc)
    ]
    failures.extend(naming_defects(doc, path))
    return failures


def scan() -> tuple[list[str], int]:
    """(failures, files examined). An empty scope is a failure, not a pass."""
    policies = list(_registries.policy_files(REPO))
    reviews = sorted(REVIEWS_DIR.rglob("*.json")) if REVIEWS_DIR.exists() else []
    failures = [f for path in policies for f in _policy_failures(path)]
    failures.extend(f for path in reviews for f in _review_failures(path))
    return failures, len(policies) + len(reviews)


#: (document, a substring of the key that must be reported): the shapes the gate forbids.
FORBIDDEN_CASES = (
    ({"theorem": [{"id": "THM-0001", "approved": True}]}, "theorem[0].approved"),
    ({"assumption": [{"id": "ASM-0001", "review_status": "ok"}]}, "review_status"),
    ({"unit": [{"id": "u", "nested": {"clean": True}}]}, "clean"),
)

#: (document, why the gate must accept it): the mechanism itself, which must keep working.
PERMITTED_CASES = (
    (
        {"theorem": [{"id": "THM-0001", "review_requirement": "Owner security-specification review"}]},
        "the gate refused `review_requirement`, which is the mechanism, not a violation",
    ),
    (
        {"reviewed_fingerprint": "sha256:abc", "reviewer": "x", "axis": "specification"},
        "the gate refused a well-formed review record",
    ),
)

#: (record, the defect it must produce or None, what it is).
NAMING_CASES = (
    ({"reviewer": "x"}, "reviewed_fingerprint", "an approval naming no fingerprint"),
    (
        {"record_kind": "measurement", "re_derived_against": "main @ abc"},
        None,
        "a well-formed measurement record",
    ),
    (
        {"record_kind": "measurement", "reviewed_fingerprint": "sha256:abc"},
        "Measuring is not approving",
        "a measurement claiming to be a review",
    ),
    ({"record_kind": "audit"}, "unknown `record_kind`", "an undeclared third kind"),
)


def _forbidden_failure() -> str | None:
    for doc, needle in FORBIDDEN_CASES:
        if not any(needle in entry for entry in offending_keys(doc)):
            return f"{needle} not caught in {doc}"
    return None


def _permitted_failure() -> str | None:
    return next((refusal for doc, refusal in PERMITTED_CASES if offending_keys(doc)), None)


def _naming_failure(doc: dict, needle: str | None, label: str) -> str | None:
    defects = naming_defects(doc, REPO / "verification" / "reviews" / "selftest.json")
    if needle is None:
        return f"the gate refused {label}: {defects}" if defects else None
    return None if any(needle in entry for entry in defects) else f"{label} was accepted"


def _first_selftest_failure() -> str | None:
    """The first way the gate misjudges one of its own cases, or None."""
    failure = _forbidden_failure() or _permitted_failure()
    for doc, needle, label in NAMING_CASES:
        failure = failure or _naming_failure(doc, needle, label)
    return failure


def selftest() -> int:
    """The gate must refuse a document that carries the thing it forbids.

    A gate whose only evidence is that a clean tree passes has never been shown to fail.
    """
    failure = _first_selftest_failure()
    if failure is not None:
        print(f"SELFTEST FAIL: {failure}", file=sys.stderr)
        return 1
    print("registry_approval_gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    failures, examined = scan()
    if examined == 0:
        # An empty scope is the gate measuring nothing while printing OK — the failure
        # mode a glob that stopped matching produces, and one this repository has shipped.
        print(
            "FAIL: registry approval gate examined 0 files. Expected the policy "
            "registries under verification/policy/.",
            file=sys.stderr,
        )
        return 1
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    exempted = ", ".join(
        f"{name}:{'/'.join(sorted(keys))}" for name, keys in sorted(EXEMPT_KEYS.items())
    )
    # What was examined AND what was exempted, on the pass line. A gate that prints only
    # OK cannot be distinguished from one whose scope quietly went empty.
    print(
        f"registry approval gate: OK ({examined} file(s) examined, no stored approvals; "
        f"exempt: {exempted})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
