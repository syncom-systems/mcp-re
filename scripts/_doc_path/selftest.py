# SPDX-License-Identifier: Apache-2.0
"""Three cases, each asserted in BOTH directions.

One direction is not a probe: a gate that always fails passes the failing half, and a
gate that never fires passes the passing half.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
from pathlib import Path

from _doc_path.scan import measure
from _doc_path.verdict import verdict

REGISTERED_ONE = (
    'schema_version = 1\n\n[[debt]]\npath = "docs/guide.md"\n'
    'dead_tokens = 1\nstatus = "unreviewed"\n'
)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _fixture(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "selftest@example.invalid")
    _git(root, "config", "user.name", "selftest")
    (root / "docs").mkdir()
    (root / "src").mkdir()
    (root / "work").mkdir()
    (root / ".gitignore").write_text("/work/\n")
    (root / "src" / "real.rs").write_text("// nothing\n")
    (root / "work" / "ATLAS.md").write_text("# local only\n")
    _git(root, "add", "-A")


def _quiet_verdict(root: Path, registry: Path) -> int:
    """`verdict`'s own verdict line, swallowed.

    A self-test states ONE verdict. Letting the runs it drives print theirs would hand
    `scripts/run_gate.sh` several verdict lines for one invocation, and a wrapper that
    cannot tell which line is the answer is the failure class it exists to remove.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return verdict(root, registry)


def _dead_token_case(root: Path, guide: Path) -> str | None:
    """1. A dead token. The gate must name it."""
    guide.write_text("See `src/definitely_not_a_real_module.rs` for the details.\n")
    found = measure(root)
    if "docs/guide.md" not in found or "definitely_not_a_real_module.rs" not in str(found):
        return f"a dead token was not caught, got {found}"
    guide.write_text("See `src/real.rs` for the details.\n")
    if measure(root):
        return "a resolving token was reported"
    return None


def _ratchet_case(root: Path, guide: Path) -> str | None:
    """2. The ratchet, through `verdict` and a registry — an entry PINS a file, it does not
    exempt one. Asserted in both directions over the same registry."""
    registry = root / "debt.toml"
    registry.write_text(REGISTERED_ONE)
    guide.write_text("`src/gone_a.rs`\n")
    if _quiet_verdict(root, registry) != 0:
        return "a file at its registered count did not pass"
    guide.write_text("`src/gone_a.rs` and `src/gone_b.rs`\n")
    if _quiet_verdict(root, registry) == 0:
        return "a registered file grew a second token and passed"
    guide.write_text("`src/real.rs`\n")
    if _quiet_verdict(root, registry) == 0:
        return "a registry entry describing paid debt passed"
    return None


def _gitignored_case(root: Path, guide: Path) -> str | None:
    """3. The gitignored token — the rule the whole class exists for. Without the passing
    half this is indistinguishable from a substring ban on `work/`."""
    guide.write_text("See `work/ATLAS.md`.\n")
    found = measure(root)
    hits = found.get("docs/guide.md", [])
    if len(hits) != 1 or "GITIGNORED" not in hits[0]:
        return f"a gitignored-only token was not caught, got {found}"
    _git(root, "add", "-f", "work/ATLAS.md")
    if measure(root):
        return "the same token failed once the path was tracked"
    return None


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        _fixture(root)
        guide = root / "docs" / "guide.md"
        for case in (_dead_token_case, _ratchet_case, _gitignored_case):
            failure = case(root, guide)
            if failure is not None:
                print(f"SELFTEST FAILED: {failure}")
                return 1
    print("doc-path gate selftest: PASS")
    return 0
