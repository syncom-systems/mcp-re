#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SDK wire-code gate — every `mcp-re.*` token the SDKs spell is a frozen wire code.

WHAT THIS PROVES, exactly: every literal `mcp-re.<name>` token in the Python and TypeScript
SDK trees (sources, native bindings and tests) is the wire code of a verdict that
`mcp-re-core`'s `ALL_ERRORS` lists. The set is read from `mcp-re-core/src/error.rs`: the
variants `ALL_ERRORS` names, each mapped through its `wire_code()` arm. A variant `ALL_ERRORS`
names with no arm is a measurement failure, not an empty set.

The SDKs spell these tokens by hand: in error messages they compare against, in the wire
codes their test fixtures put into simulated server receipts, and in documentation. A token
no server can emit makes a fixture model a receipt that never occurs, and makes a host-side
comparison one that never matches.

A token followed by `.` is a namespaced key, not a wire code (`se.syncom/mcp-re.http.request`),
and is not checked.

WHAT IT DOES NOT PROVE: that a token is the RIGHT code for its site, or anything about codes
the SDKs build at runtime rather than spell.

Run:  python3 scripts/sdk_wire_code_gate.py
      python3 scripts/sdk_wire_code_gate.py --selftest
      python3 scripts/sdk_wire_code_gate.py --probe     # a planted token in a real file is red
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ERROR_RS = Path("mcp-re-core/src/error.rs")
SDK_TREES = (Path("sdk/python"), Path("sdk/typescript"))
SKIP_DIRS = frozenset({"node_modules", "dist", "coverage", "target", "site-packages", "__pycache__", ".pytest_cache"})


def _skipped(directory: str) -> bool:
    """A vendored, built or environment tree: none of its files is SDK source."""
    return directory in SKIP_DIRS or directory.startswith(".venv")
SCANNED_SUFFIXES = frozenset({".rs", ".py", ".ts", ".mts", ".js", ".md"})

TOKEN = re.compile(r"mcp-re\.[A-Za-z0-9_]+(?![.A-Za-z0-9_])")
ARM = re.compile(
    r"McpReError::(\w+)\s*(?:\{[^}]*\}|\([^)]*\))?\s*=>\s*(?:\{\s*)?\"(mcp-re\.[a-z0-9_]+)\""
)
LISTED = re.compile(r"McpReError::(\w+)")


class MeasurementError(Exception):
    """The frozen set could not be read; the gate refuses rather than compare to nothing."""


def _region(source: str, opener: str, closer: str) -> str:
    start = source.find(opener)
    if start < 0:
        raise MeasurementError(f"{ERROR_RS}: `{opener.strip()}` not found")
    end = source.find(closer, start)
    if end < 0:
        raise MeasurementError(f"{ERROR_RS}: `{opener.strip()}` is not closed by `{closer}`")
    return source[start:end]


def frozen_codes(error_rs: str) -> set[str]:
    """The wire codes of the variants `ALL_ERRORS` lists."""
    arms = dict(ARM.findall(_region(error_rs, "    pub fn wire_code(", "\n    }\n")))
    listed = LISTED.findall(_region(error_rs, "pub const ALL_ERRORS", "];"))
    if not arms or not listed:
        raise MeasurementError(f"{ERROR_RS}: read {len(arms)} wire_code arm(s) and {len(listed)} ALL_ERRORS entr(ies)")
    unmapped = sorted(set(listed) - set(arms))
    if unmapped:
        raise MeasurementError(f"{ERROR_RS}: ALL_ERRORS lists {unmapped} with no wire_code arm")
    return {arms[variant] for variant in listed}


def sdk_files(root: Path) -> list[Path]:
    """Every scanned file in the SDK trees under `root`, sorted."""
    out: list[Path] = []
    for tree in SDK_TREES:
        for directory, subdirs, files in os.walk(root / tree):
            subdirs[:] = sorted(d for d in subdirs if not _skipped(d))
            out.extend(Path(directory) / f for f in files if Path(f).suffix in SCANNED_SUFFIXES)
    return sorted(out)


def problems(root: Path) -> list[str]:
    codes = frozen_codes((root / ERROR_RS).read_text(encoding="utf-8"))
    found: list[str] = []
    files = sdk_files(root)
    if not files:
        raise MeasurementError(f"no SDK file found under {', '.join(str(t) for t in SDK_TREES)}")
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for token in TOKEN.findall(line):
                if token not in codes:
                    rel = path.relative_to(root).as_posix()
                    found.append(f"{rel}:{number}: `{token}` is not a frozen wire code (ALL_ERRORS)")
    return found


def run(root: Path) -> int:
    try:
        found = problems(root)
    except MeasurementError as exc:
        print(f"sdk wire-code gate: FAIL — {exc}")
        return 1
    if found:
        print(f"sdk wire-code gate: FAIL — {len(found)} problem(s)")
        for line in found:
            print(f"  - {line}")
        return 1
    print(f"sdk wire-code gate: OK — every `mcp-re.*` token in {len(sdk_files(root))} SDK file(s) is a frozen wire code")
    return 0


_ERROR_RS = '''impl McpReError {
    pub fn wire_code(&self) -> &'static str {
        match self {
            McpReError::ReplayDetected => "mcp-re.replay_detected",
            McpReError::InvalidSignature { .. } => {
                "mcp-re.invalid_signature"
            }
        }
    }
}

pub const ALL_ERRORS: &[McpReError] = &[
    McpReError::ReplayDetected,
    McpReError::InvalidSignature,
];
'''


def _tree(files: dict[str, str], error_rs: str = _ERROR_RS) -> Path:
    root = Path(tempfile.mkdtemp(prefix="sdk-wire-code-"))
    for rel, text in {str(ERROR_RS): error_rs, **files}.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def selftest() -> int:
    failures = 0

    def case(label: str, ok: bool, detail: object = None) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f" — got {detail!r}"))
        if not ok:
            failures += 1

    clean = {
        "sdk/python/tests/t.py": 'assert e == "mcp-re.replay_detected"\nKEY = "se.syncom/mcp-re.http.request"\n',
        "sdk/typescript/src/lib.rs": '// fails closed as `mcp-re.invalid_signature`; any `mcp-re.*` code\n',
    }
    case("frozen tokens and a namespaced key pass", problems(_tree(clean)) == [], problems(_tree(clean)))

    drifted = {**clean, "sdk/typescript/test/t.test.ts": 'wireCode: "mcp-re.upstream_unavailable",\n'}
    got = problems(_tree(drifted))
    case("a token outside ALL_ERRORS is red, with its site",
         len(got) == 1 and "t.test.ts:1" in got[0] and "mcp-re.upstream_unavailable" in got[0], got)

    vendored = {
        **clean,
        "sdk/typescript/node_modules/x/index.js": '"mcp-re.not_a_code"\n',
        "sdk/python/.venv312/lib/site.py": '"mcp-re.not_a_code"\n',
    }
    case("vendored and built trees are not scanned", problems(_tree(vendored)) == [], problems(_tree(vendored)))

    unlisted = _ERROR_RS.replace("    McpReError::InvalidSignature,\n", "")
    got = problems(_tree(clean, unlisted))
    case("a code whose variant ALL_ERRORS omits is not frozen", len(got) == 1 and "invalid_signature" in got[0], got)

    unmapped = _ERROR_RS.replace('            McpReError::ReplayDetected => "mcp-re.replay_detected",\n', "")
    try:
        problems(_tree(clean, unmapped))
        case("an ALL_ERRORS variant with no wire_code arm is a measurement failure", False, "no error")
    except MeasurementError:
        case("an ALL_ERRORS variant with no wire_code arm is a measurement failure", True)

    try:
        problems(_tree({}))
        case("no SDK file is a measurement failure, not a pass", False, "no error")
    except MeasurementError:
        case("no SDK file is a measurement failure, not a pass", True)

    real = frozen_codes((REPO / ERROR_RS).read_text(encoding="utf-8"))
    case("the real error.rs yields the frozen set", "mcp-re.replay_detected" in real and len(real) > 10, len(real))

    if failures:
        print(f"sdk wire-code gate selftest: FAIL ({failures} case(s))")
        return 1
    print("sdk wire-code gate selftest: PASS (frozen and namespaced tokens pass, a drifted token is red at its "
          "site, vendored trees are skipped, the set is ALL_ERRORS through wire_code, and an unreadable set refuses)")
    return 0


def probe() -> int:
    """Inject a token outside ALL_ERRORS into a copy of a real SDK file and require red."""
    victim = Path("sdk/typescript/test/transport.test.ts")
    planted = "mcp-re.not_a_frozen_code"
    text = (REPO / victim).read_text(encoding="utf-8")
    root = _tree({str(victim): text + f'// "{planted}"\n'}, (REPO / ERROR_RS).read_text(encoding="utf-8"))
    got = problems(root)
    if len(got) == 1 and planted in got[0] and str(victim) in got[0]:
        print(f"sdk wire-code probe: PASS — a planted `{planted}` in {victim} is reported against the real ALL_ERRORS")
        return 0
    print(f"sdk wire-code probe: FAIL — the planted token was not the one problem reported: {got!r}")
    return 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(probe() if "--probe" in sys.argv else run(REPO))
