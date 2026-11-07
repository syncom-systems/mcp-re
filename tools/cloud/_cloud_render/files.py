# SPDX-License-Identifier: Apache-2.0
"""The file contract: ignored run directory, never overwritten, manifest, re-verification."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

from _cloud_render.check import Refused
from _cloud_render.render import render

RUNS = Path("work") / "cloud-runs"
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}")


class Template(NamedTuple):
    """A tracked template: where it lives in the repository, and the bytes it holds."""

    rel: str
    raw: bytes


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _is_ignored(path: Path, repo: Path) -> bool:
    result = subprocess.run(["git", "-C", str(repo), "check-ignore", "-q", str(path)], capture_output=True)
    return result.returncode == 0


def _refuse_untracked_destination(out: Path, repo: Path) -> None:
    if not _is_ignored(out, repo):
        raise Refused(f"{out.relative_to(repo)} is not git-ignored; a rendered cloud configuration never "
                      "goes where it could be committed")


def _manifest(template: Template, rendered: bytes, values: dict[str, str], name: str) -> dict:
    return {
        "template": template.rel,
        "template_sha256": _sha256(template.raw),
        "values": dict(sorted(values.items())),
        "rendered": name,
        "rendered_sha256": _sha256(rendered),
    }


def _write_run(out: Path, template: Template, rendered: bytes, values: dict[str, str]) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(rendered)
    manifest = _manifest(template, rendered, values, out.name)
    (out.parent / f"{out.name}.render.json").write_text(json.dumps(manifest, indent=2) + "\n")


def materialize(repo: Path, template_rel: str, run_id: str, values: dict[str, str]) -> Path:
    if not RUN_ID.fullmatch(run_id):
        raise Refused(f"run id {run_id!r} must match {RUN_ID.pattern}")
    template_path = repo / template_rel
    raw = template_path.read_bytes()
    rendered = render(raw.decode("utf-8"), values).encode("utf-8")
    out = repo / RUNS / run_id / template_path.name
    _refuse_untracked_destination(out, repo)
    if out.exists():
        if out.read_bytes() != rendered:
            raise Refused(f"{out.relative_to(repo)} exists with different content; the file a run was "
                          "created from is kept for its teardown, never overwritten")
        return out
    _write_run(out, Template(template_rel, raw), rendered, values)
    return out


def verify(rendered: Path) -> str:
    manifest = json.loads(rendered.with_name(rendered.name + ".render.json").read_text())
    actual = _sha256(rendered.read_bytes())
    if actual != manifest["rendered_sha256"]:
        raise Refused(f"{rendered} changed since it was rendered ({actual} != {manifest['rendered_sha256']})")
    return actual
