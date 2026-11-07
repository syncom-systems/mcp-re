# SPDX-License-Identifier: Apache-2.0
"""Finishing a run: the summary, the SHA256SUMS seal, and the archive."""

from __future__ import annotations

import tarfile
from pathlib import Path

from analysis import render_markdown, summarize_run
from common import log, read_json, sha256_file, utc_now, write_json


def finish(run_dir: Path, vcpus: int) -> dict:
    summary = summarize_run(run_dir, vcpus)
    write_json(run_dir / "summary.json", summary)
    manifest = read_json(run_dir / "manifest.json")
    manifest["finished"] = utc_now()
    write_json(run_dir / "manifest.json", manifest)
    (run_dir / "summary.md").write_text(render_markdown(summary, manifest))
    log(run_dir, f"summary: {summary['ceiling']['statement']}")
    seal(run_dir)
    return summary


def seal(run_dir: Path) -> None:
    """SHA256SUMS over every file in the run directory, written after the last write to any."""
    sums = []
    for path in sorted(p for p in run_dir.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        sums.append(f"{sha256_file(path).split(':', 1)[1]}  {path.relative_to(run_dir)}")
    (run_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n")


def pack(run_dir: Path) -> Path:
    """Re-seal (the launcher and a diagnose pass write after `finish`), then archive the run
    directory beside itself with a `sha256sum -c`-readable digest file."""
    seal(run_dir)
    archive = run_dir.parent / f"{run_dir.name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(run_dir, arcname=run_dir.name)
    digest = sha256_file(archive).split(":", 1)[1]
    (run_dir.parent / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n")
    return archive
