# SPDX-License-Identifier: Apache-2.0
"""The manifest, the fingerprint encoding and the perturbation seams the measured-inputs
tests share.

`test_measured_inputs.py` runs the cases; each `_measured_inputs_*.py` module holds the
cases of one proposition about what a fingerprint covers. They all measure the REAL
manifest, so the loaded documents live here once.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import _tree  # noqa: E402
from _assumptions import load_assumptions  # noqa: E402
from _fingerprint import fingerprint_unit  # noqa: E402
from _manifest import load_verification  # noqa: E402
from _toolchain_lock import load_toolchains  # noqa: E402
from _trust_boundaries import load_trust_boundaries  # noqa: E402

DOC = load_verification()
TOOLCHAINS = load_toolchains()
ASSUMPTIONS = load_assumptions()
UNITS = {unit["id"]: unit for unit in DOC.get("unit", [])}
BOUNDARIES_REAL = load_trust_boundaries()


def measure(unit: dict, doc=None, assumptions=None, boundaries=None) -> dict:
    """The fingerprint of `unit` over the real manifest, unless a case substitutes one of
    the documents the encoding reads."""
    return fingerprint_unit(
        unit,
        DOC if doc is None else doc,
        TOOLCHAINS,
        ASSUMPTIONS if assumptions is None else assumptions,
        boundaries,
    )


def components(unit_id: str) -> dict:
    return measure(UNITS[unit_id])["components"]


def fingerprints(unit_ids) -> dict[str, str]:
    """Each named unit's fingerprint, over the real manifest."""
    return {unit_id: measure(UNITS[unit_id])["fingerprint"] for unit_id in unit_ids}


def scoped(*targets):
    return {"assumption": [{"id": "ASM-X", "scope": list(targets)}]}


def while_perturbed(path: str, observe):
    """`observe()` evaluated while `path` READS as carrying one extra line.

    The property under test is that the DIGEST of that file reaches the fingerprint, so the
    bytes the fingerprint reads must move; asserting a component's key set would prove only
    the intention. They move in what `Path.read_bytes` and `Path.read_text` return for that
    one file and nowhere else — never in the file itself. Writing the tracked file and
    restoring it in a `finally` leaves the falsifier line in the tree whenever the process
    dies inside the window, which is how `# falsifier` once reached a working copy.

    The observation happens INSIDE the window on purpose. Returning the file first and
    measuring second is how a falsifier ends up measuring the restored tree and passing
    whatever it was meant to catch — which is what the first draft of this helper did."""
    from _manifest import REPO_ROOT as ROOT

    target = (ROOT / path).resolve()
    original = target.read_bytes()
    perturbed = original + b"\n# falsifier\n"
    real_bytes, real_text = Path.read_bytes, Path.read_text

    def read_bytes(self):
        return perturbed if self.resolve() == target else real_bytes(self)

    def read_text(self, encoding=None, errors=None, *args, **kwargs):
        if self.resolve() == target:
            return perturbed.decode(encoding or "utf-8", errors or "strict")
        return real_text(self, encoding, errors, *args, **kwargs)

    Path.read_bytes, Path.read_text = read_bytes, read_text
    try:
        assert target.read_bytes() != original
        return observe()
    finally:
        Path.read_bytes, Path.read_text = real_bytes, real_text
        assert target.read_bytes() == original


class PerturbedTree(_tree.WorkingTree):
    """The checkout, except that `path` reads as carrying one extra line."""

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path

    def read(self, rel: str) -> bytes:
        data = super().read(rel)
        return data + b"\n# falsifier\n" if rel == self.path else data


def perturbed_fingerprints(path: str, unit_ids):
    """Unit fingerprints measured over a tree in which `path` is perturbed.

    Through the source-tree seam rather than by patching the filesystem: the fingerprint
    reads only `_tree.current()`, so the perturbation reaches it and nothing else, and the
    file itself is never written."""
    with _tree.reading(PerturbedTree(path)):
        return {
            unit_id: measure(UNITS[unit_id])["fingerprint"]
            for unit_id in unit_ids
        }
