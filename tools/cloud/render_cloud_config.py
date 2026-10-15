#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render a tracked cloud-configuration template to an UNTRACKED file under `work/`.

THE FAILURE CLASS. The EKS runbook told the operator to run
`sed -i "s|OPERATOR_CIDR|…|" deploy/eks/mcp-re-slo-cluster.yaml`. Three defects in one line:
it rewrites a TRACKED file in place (the run's address lands in the working tree, one
`git commit -a` from being published, and the template is gone for the next run); BSD `sed`
reads `-i "s|…|"` as a backup suffix and fails on macOS; and nothing preserves the exact file
`eksctl create` consumed, so teardown runs against whatever the file says by then.

The rule this tool enforces for every cloud configuration that needs substitution:
  * the tracked template is never modified — placeholders are `@@NAME@@` and stay there;
  * the rendered file goes to `work/cloud-runs/<run-id>/`, which git ignores, and is
    refused anywhere else;
  * an unresolved placeholder, an open-to-the-world network (`0.0.0.0/0`, `::/0`) and an
    invalid or prefix-0 `*_CIDR` value are refused;
  * the rendered bytes are kept, never overwritten, with a manifest recording the template
    digest, the values and the rendered digest — `--verify` re-checks them before teardown,
    so teardown provably uses the file creation used.

Run:  python3 tools/cloud/render_cloud_config.py --template T --run-id ID --set NAME=VALUE ...
      python3 tools/cloud/render_cloud_config.py --verify work/cloud-runs/ID/<file>
      python3 tools/cloud/render_cloud_config.py --selftest
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
RUNS = Path("work") / "cloud-runs"
PLACEHOLDER = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
VALUE = re.compile(r"[A-Za-z0-9:][A-Za-z0-9.:/_+=-]*")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}")
OPEN_WORLD = re.compile(r"(?<![\d.])0\.0\.0\.0/0\b|(?<![\w:])::/0\b")


class Refused(ValueError):
    pass


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _without_comments(text: str) -> str:
    """YAML/shell-style comment lines and trailing ` # …` dropped; JSON has none."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(re.sub(r"\s#\s.*$", "", line))
    return "\n".join(out)


def check_value(name: str, value: str) -> None:
    if not VALUE.fullmatch(value):
        raise Refused(f"{name}={value!r}: values are restricted to {VALUE.pattern}")
    if name.endswith("_CIDR"):
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise Refused(f"{name}={value!r} is not a network in CIDR form: {exc}") from exc
        if network.prefixlen == 0:
            raise Refused(f"{name}={value!r} opens the resource to the whole internet")


def render(template: str, values: dict[str, str]) -> str:
    for name, value in values.items():
        check_value(name, value)
    named = set(PLACEHOLDER.findall(template))
    unused = sorted(set(values) - named)
    if unused:
        raise Refused(f"value(s) for placeholder(s) the template does not have: {', '.join(unused)}")
    out = PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), template)
    left = sorted(set(PLACEHOLDER.findall(out)))
    if left:
        raise Refused(f"unresolved placeholder(s): {', '.join(left)}")
    if OPEN_WORLD.search(_without_comments(out)):
        raise Refused("the rendered configuration opens a network to the whole internet (0.0.0.0/0 or ::/0)")
    return out


def _is_ignored(path: Path, repo: Path) -> bool:
    result = subprocess.run(["git", "-C", str(repo), "check-ignore", "-q", str(path)], capture_output=True)
    return result.returncode == 0


def materialize(repo: Path, template_rel: str, run_id: str, values: dict[str, str]) -> Path:
    if not RUN_ID.fullmatch(run_id):
        raise Refused(f"run id {run_id!r} must match {RUN_ID.pattern}")
    template_path = repo / template_rel
    raw = template_path.read_bytes()
    rendered = render(raw.decode("utf-8"), values).encode("utf-8")
    out_dir = repo / RUNS / run_id
    out = out_dir / template_path.name
    if not _is_ignored(out, repo):
        raise Refused(f"{out.relative_to(repo)} is not git-ignored; a rendered cloud configuration never "
                      "goes where it could be committed")
    if out.exists():
        if out.read_bytes() != rendered:
            raise Refused(f"{out.relative_to(repo)} exists with different content; the file a run was "
                          "created from is kept for its teardown, never overwritten")
        return out
    out_dir.mkdir(parents=True, exist_ok=True)
    out.write_bytes(rendered)
    manifest = {
        "template": template_rel,
        "template_sha256": _sha256(raw),
        "values": dict(sorted(values.items())),
        "rendered": out.name,
        "rendered_sha256": _sha256(rendered),
    }
    (out_dir / f"{out.name}.render.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return out


def verify(rendered: Path) -> str:
    manifest = json.loads(rendered.with_name(rendered.name + ".render.json").read_text())
    actual = _sha256(rendered.read_bytes())
    if actual != manifest["rendered_sha256"]:
        raise Refused(f"{rendered} changed since it was rendered ({actual} != {manifest['rendered_sha256']})")
    return actual


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    try:
        if argv[:1] == ["--verify"] and len(argv) == 2:
            print(f"verified: {argv[1]} {verify(Path(argv[1]))}")
            return 0
        args: dict[str, str | None] = {"template": None, "run_id": None}
        values: dict[str, str] = {}
        it = iter(argv)
        for arg in it:
            if arg == "--template":
                args["template"] = next(it)
            elif arg == "--run-id":
                args["run_id"] = next(it)
            elif arg == "--set":
                name, sep, value = next(it).partition("=")
                if not sep:
                    raise Refused("--set takes NAME=VALUE")
                values[name] = value
            else:
                raise Refused(f"unknown argument {arg!r}")
        if not args["template"] or not args["run_id"]:
            raise Refused("--template and --run-id are required")
        out = materialize(REPO, str(args["template"]), str(args["run_id"]), values)
        print(out.relative_to(REPO))
        return 0
    except (Refused, StopIteration, FileNotFoundError) as exc:
        print(f"render_cloud_config: REFUSED — {exc}", file=sys.stderr)
        return 1


def selftest() -> int:
    template = "endpoint:\n  # eksctl's default would be 0.0.0.0/0 — this comment is not config\n" \
               "  publicAccessCIDRs:\n    - @@OPERATOR_CIDR@@\n"
    assert "    - 192.0.2.7/32" in render(template, {"OPERATOR_CIDR": "192.0.2.7/32"})
    for values, needle in (
        ({}, "unresolved"),
        ({"OPERATOR_CIDR": "0.0.0.0/0"}, "whole internet"),
        ({"OPERATOR_CIDR": "::/0"}, "whole internet"),
        ({"OPERATOR_CIDR": "192.0.2.7/33"}, "CIDR form"),
        ({"OPERATOR_CIDR": "192.0.2.7/24"}, "CIDR form"),          # host bits set
        ({"OPERATOR_CIDR": "$(curl x)/32"}, "restricted"),
        ({"OPERATOR_CIDR": "192.0.2.7/32", "EXTRA": "x"}, "does not have"),
    ):
        try:
            render(template, values)
        except Refused as exc:
            assert needle in str(exc), (values, str(exc))
        else:
            raise AssertionError(f"rendered {values}")
    try:
        render("cidrs: [0.0.0.0/0, @@OPERATOR_CIDR@@]\n", {"OPERATOR_CIDR": "192.0.2.7/32"})
    except Refused as exc:
        assert "whole internet" in str(exc)
    else:
        raise AssertionError("a literal open-world CIDR in the template body rendered")

    # The file contract, in a throwaway repository: the tracked template is untouched, the
    # output lands in the ignored run directory, is never overwritten, and --verify catches
    # an edit made after creation.
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / ".gitignore").write_text("/work/\n")
        (repo / "deploy").mkdir()
        tracked = repo / "deploy" / "cluster.yaml"
        tracked.write_text(template)
        before = tracked.read_bytes()
        out = materialize(repo, "deploy/cluster.yaml", "run-1", {"OPERATOR_CIDR": "192.0.2.7/32"})
        assert tracked.read_bytes() == before, "the tracked template was modified"
        assert out == repo / "work" / "cloud-runs" / "run-1" / "cluster.yaml"
        assert verify(out).startswith("sha256:")
        assert materialize(repo, "deploy/cluster.yaml", "run-1", {"OPERATOR_CIDR": "192.0.2.7/32"}) == out
        try:
            materialize(repo, "deploy/cluster.yaml", "run-1", {"OPERATOR_CIDR": "198.51.100.1/32"})
        except Refused as exc:
            assert "never overwritten" in str(exc)
        else:
            raise AssertionError("a run's rendered file was overwritten")
        out.write_text(out.read_text() + "# edited\n")
        try:
            verify(out)
        except Refused as exc:
            assert "changed since" in str(exc)
        else:
            raise AssertionError("verify accepted an edited rendered file")
        (repo / ".gitignore").write_text("")
        try:
            materialize(repo, "deploy/cluster.yaml", "run-2", {"OPERATOR_CIDR": "192.0.2.7/32"})
        except Refused as exc:
            assert "not git-ignored" in str(exc)
        else:
            raise AssertionError("rendered into a path git would track")
    print("render_cloud_config selftest: OK (template untouched; open-world, unresolved and overwrite refused)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
