# SPDX-License-Identifier: Apache-2.0
"""Run clippy over the production targets and count the adopted lints' primary spans per crate."""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

import _rust_targets

from _clippy_ratchet.config import ADOPTED, REPO, STRICT_CONF_LABEL

_PRODUCTION_SPAN = re.compile(r"^[^/]+/src/")


def _command(targets: list[str]) -> list[str]:
    flags = [f"--@rules_rust//rust/settings:clippy_flag={f}"
             for f in (f"-Wclippy::{lint}" for lint in ADOPTED)]
    return ["bazel", "build", "--aspects=@rules_rust//rust:defs.bzl%rust_clippy_aspect",
            "--output_groups=clippy_output",
            f"--@rules_rust//rust/settings:clippy.toml={STRICT_CONF_LABEL}",
            "--@rules_rust//rust/settings:clippy_output_diagnostics=True",
            "--@rules_rust//rust/settings:clippy_error_format=json",
            *flags, *targets]


def _json_lines(text: str) -> Iterator[dict]:
    for line in text.splitlines():
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _target_diagnostics(target: str, root: Path) -> list[dict]:
    pkg, name = target[2:].split(":", 1)
    out = root / "bazel-bin" / pkg / f"{name}.clippy.diagnostics"
    if not out.is_file():
        return []
    text = out.read_text(encoding="utf-8", errors="replace")
    return [m for m in _json_lines(text) if m.get("$message_type") == "diagnostic"]


def clippy_diagnostics(targets: list[str], root: Path = REPO) -> tuple[int, str, list[dict]]:
    """Lint `targets` with the adopted lints on, and return every diagnostic clippy wrote.

    The diagnostics are CAPTURED to a file per target (`clippy_output_diagnostics`) rather
    than read off the console, because a cached action prints nothing: a second run over an
    unchanged tree would otherwise report zero occurrences of everything.
    """
    proc = subprocess.run(_command(targets), cwd=root, capture_output=True, text=True)
    diagnostics: list[dict] = []
    for target in targets:
        diagnostics += _target_diagnostics(target, root)
    return proc.returncode, proc.stderr, diagnostics


def clippy_code(message: dict) -> str:
    """The lint code of a diagnostic, e.g. `clippy::expect_used`, or "" when it has none."""
    return (message.get("code") or {}).get("code") or ""


def primary_spans(message: dict) -> list[dict]:
    return [x for x in message.get("spans", []) if x.get("is_primary")]


def _require_compiled(rc: int, stderr: str) -> None:
    """A non-zero status means the tree DID NOT COMPILE, and a clippy run that could not
    compile a target has not measured it — it reports zero occurrences of every lint in
    it. The gate would then say "down to 0 from a baseline of 40 — lower the baseline",
    which is the worst possible instruction: it would erase the debt register for code
    nobody linted. LINT_FLAGS are all `-W`, so warnings alone never set a non-zero status.
    """
    if rc == 0:
        return
    errors = [ln for ln in stderr.splitlines() if ln.startswith(("error", "ERROR"))]
    raise RuntimeError(
        f"clippy did not compile the production targets, so it measured nothing "
        f"(exit {rc}). A partial build reports ZERO occurrences for every target it "
        f"could not lint.\n" + ("\n".join(errors[:20]) or stderr[-4000:] or "(no stderr)")
    )


def _production_site(message: dict) -> tuple[str, int, int, str] | None:
    """(file, line, column, lint) of a clippy diagnostic whose primary span is in a crate's `src/`."""
    code = clippy_code(message)
    if not code.startswith("clippy::"):
        return None
    spans = primary_spans(message)
    if not spans or not _PRODUCTION_SPAN.match(spans[0]["file_name"]):
        return None
    return (spans[0]["file_name"], spans[0]["line_start"], spans[0]["column_start"],
            code.split("::", 1)[1])


def measure(root: Path) -> tuple[Counter, int]:
    """Run clippy over the production targets and count primary spans per (crate, lint).

    A site is counted ONCE however many flavors compile it, and only in a crate's `src/`:
    examples, `tests/` and the probes are not production code.

    Returns (counter keyed by "crate::lint", number of compiler messages seen).
    """
    # The test-support flavors are `testonly`, so the table's projection leaves them out:
    # the ruling exempts test code, and those flavors exist to compile it.
    targets = _rust_targets.production_targets()
    if not targets:
        raise RuntimeError("the build graph holds no production Rust target — nothing measured")
    rc, stderr, diagnostics = clippy_diagnostics(targets, root)
    _require_compiled(rc, stderr)
    sites = {site for site in map(_production_site, diagnostics) if site is not None}
    counts: Counter = Counter(f"{path.split('/')[0]}::{lint}" for path, _, _, lint in sites)
    return counts, len(diagnostics)
