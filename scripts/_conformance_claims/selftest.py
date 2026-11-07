# SPDX-License-Identifier: Apache-2.0
"""Each claim shape the gate exists to refuse goes red; the honest one stays green."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _conformance_claims.check import check
from _conformance_claims.config import GUIDE, VECTORS_ROOT
from _conformance_claims.selftest_cases import CASES, PLAIN, Case


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture(root: Path, case: Case) -> None:
    _write(root, GUIDE, case.guide)
    _write(root, "mcp-re-conformance/BUILD.bazel", case.build)
    _write(root, f"{VECTORS_ROOT}/alpha/manifest.json", case.manifest)
    _write(root, "mcp-re-conformance/tests/alpha_test.rs", "fn t() {}\n")
    _write(
        root,
        "mcp-re-conformance/tests/pinning_test.rs",
        "assert_eq!(corpus_digest(&m.fixtures), m.corpus_digest);\n",
    )
    if "does not advertise" in case.expected:
        _write(root, f"{VECTORS_ROOT}/unlisted/manifest.json", PLAIN)


def _run_case(case: Case) -> bool:
    """True when the case went wrong."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _fixture(root, case)
        failures = check(root)
    ok = not failures if not case.expected else any(case.expected in f for f in failures)
    print(f"  {'ok  ' if ok else 'FAIL'}  {case.label}")
    if not ok:
        print(f"        got {failures}")
    return not ok


def selftest() -> int:
    failed = [_run_case(case) for case in CASES]
    if any(failed):
        print("conformance-claims gate: SELFTEST FAILED")
        return 1
    print("conformance-claims gate: selftest passed")
    return 0
