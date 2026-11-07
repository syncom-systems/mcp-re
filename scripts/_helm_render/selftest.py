# SPDX-License-Identifier: Apache-2.0
"""The selftest: each text check goes red on a copy of the tree with the drift it exists to catch."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from _helm_render.checks import TEXT_CHECKS, TEXT_INPUTS
from _helm_render.config import REPO, TABLE_RELATIVE
from _helm_render.text_image import check_image_declares_non_root

Edit = Callable[[str], str]


def _without_feature(table: str, feature: str) -> str:
    """The target table with `feature` removed from every row that carries it."""
    data = json.loads(table)
    for row in data["targets"].values():
        if feature in row.get("features", []):
            row["features"] = [f for f in row["features"] if f != feature]
    return json.dumps(data)


def _bumped(pattern: str) -> Edit:
    """An edit that adds one to the number the second group of `pattern` captures."""
    def bump(match: re.Match[str]) -> str:
        return f"{match.group(1)}{int(match.group(2).replace('_', '')) + 1}"

    return lambda text: re.sub(pattern, bump, text)


def _with_eventual_delivery(text: str) -> str:
    return text.replace('"required" => Ok(AuditDeliveryKind::Required),',
                        '"required" => Ok(AuditDeliveryKind::Required),\n'
                        '        "eventual" => Ok(AuditDeliveryKind::Required),')


#: Per text check, the one file it reads and the edit that makes it drift.
DRIFT_EDITS: dict[str, tuple[str, Edit]] = {
    "the default image serves every offered keySource": (
        TABLE_RELATIVE, lambda text: _without_feature(text, "gcp_kms_keysource"),
    ),
    "the proxy image declares the chart's non-root uid": (
        "deploy/docker/Dockerfile", lambda text: text.replace("USER 65532:65532", "USER 0:0"),
    ),
    "the documented in-flight default is the code's": (
        "mcp-re-proxy/src/config_state/in_flight_limit.rs",
        _bumped(r"(DEFAULT_PER_CORE_IN_FLIGHT: usize = )(\d+)"),
    ),
    "the documented handshake-signing capacity is the code's": (
        "mcp-re-proxy/src/delegated_tls/sign_capacity.rs",
        _bumped(r"(pub const DEFAULT_BURST: u32 = )(\d+)"),
    ),
    "the documented continuation bound is the code's": (
        "mcp-re-proxy/src/continuation_store/capacity.rs",
        _bumped(r"(pub const MAX_LIVE_ENTRIES: u32 = )([0-9_]+)"),
    ),
    "the drain arithmetic budgets the code's audit flush": (
        "mcp-re-proxy/src/audit_sink/drain.rs",
        _bumped(r"(AUDIT_FLUSH_TIMEOUT: Duration = Duration::from_secs\()(\d+)"),
    ),
    "the chart's audit deliveries are the parser's": (
        "mcp-re-proxy/src/cli/audit_flags.rs", _with_eventual_delivery,
    ),
}


class Tally:
    """Prints each selftest verdict and counts the failures."""

    def __init__(self) -> None:
        self.failures = 0

    def case(self, label: str, ok: bool, detail: object) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}: {detail}")
        self.failures += not ok


def _copy_inputs(root: Path) -> None:
    for rel in TEXT_INPUTS:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, root / rel)


def _drift_case(root: Path, tally: Tally, label: str, check: Callable[[Path], list[str]]) -> None:
    rel, edit = DRIFT_EDITS[label]
    path = root / rel
    original = path.read_text(encoding="utf-8")
    edited = edit(original)
    if edited == original:
        tally.case(f"drift: {label}", False, f"the edit to {rel} changed nothing")
        return
    path.write_text(edited, encoding="utf-8")
    problems = check(root)
    path.write_text(original, encoding="utf-8")
    tally.case(f"drift: {label}", bool(problems), problems or "NOT refused")


def _root_agreeing_case(root: Path, tally: Tally) -> None:
    """Root in the image AND the chart agrees with itself, so only the non-root rule
    can refuse it; the uid-equality rule would pass it."""
    dockerfile = root / "deploy/docker/Dockerfile"
    values = root / "deploy/helm/mcp-re-proxy/values.yaml"
    saved = dockerfile.read_text(encoding="utf-8"), values.read_text(encoding="utf-8")
    dockerfile.write_text(saved[0].replace("USER 65532:65532", "USER 0:0"), encoding="utf-8")
    values.write_text(re.sub(r"^(\s*(?:runAsUser|runAsGroup|fsGroup):\s*)65532",
                             r"\g<1>0", saved[1], flags=re.M), encoding="utf-8")
    problems = check_image_declares_non_root(root)
    dockerfile.write_text(saved[0], encoding="utf-8")
    values.write_text(saved[1], encoding="utf-8")
    tally.case("drift: an image and a chart that agree on uid 0", bool(problems),
               problems or "NOT refused")


def selftest() -> int:
    """Each text check goes red on a copy of the tree with the drift it exists to catch.

    The seven checks run over a temporary copy of the files they read, first unchanged, then
    with one edit each: the image running as root, and a code constant the chart documents
    changed under it. No `helm` render runs; the render matrix needs the binary.
    """
    tally = Tally()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _copy_inputs(root)
        for label, check in TEXT_CHECKS:
            problems = check(root)
            tally.case(f"clean: {label}", not problems, problems or "clean")
        for label, check in TEXT_CHECKS:
            _drift_case(root, tally, label, check)
        _root_agreeing_case(root, tally)

    if tally.failures:
        print(f"helm render gate selftest: FAIL ({tally.failures})")
        return 1
    print("helm render gate selftest: PASS")
    return 0
