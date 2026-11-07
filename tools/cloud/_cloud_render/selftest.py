# SPDX-License-Identifier: Apache-2.0
"""The tool's own assertions: refusals, the source-list shape, and the file contract in a throwaway repo."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from _cloud_render.check import Refused
from _cloud_render.files import materialize, verify
from _cloud_render.render import render

TEMPLATE = (
    "endpoint:\n  # eksctl's default would be 0.0.0.0/0 — this comment is not config\n"
    "  publicAccessCIDRs:\n    - @@OPERATOR_CIDR@@\n"
)
SOURCES_TEMPLATE = '{"cidrs": ["@@OPERATOR_CIDRS@@"]}'
OPERATOR = {"OPERATOR_CIDR": "192.0.2.7/32"}


def _assert_refused(needle: str, subject, *args) -> None:
    try:
        subject(*args)
    except Refused as exc:
        assert needle in str(exc), (args, str(exc))
    else:
        raise AssertionError(f"accepted {args!r}")


def _single_value_cases() -> None:
    assert "    - 192.0.2.7/32" in render(TEMPLATE, OPERATOR)
    for values, needle in (
        ({}, "unresolved"),
        ({"OPERATOR_CIDR": "0.0.0.0/0"}, "whole internet"),
        ({"OPERATOR_CIDR": "::/0"}, "whole internet"),
        ({"OPERATOR_CIDR": "192.0.2.7/33"}, "CIDR form"),
        ({"OPERATOR_CIDR": "192.0.2.7/24"}, "CIDR form"),          # host bits set
        ({"OPERATOR_CIDR": "$(curl x)/32"}, "restricted"),
        ({"OPERATOR_CIDR": "192.0.2.7/32", "EXTRA": "x"}, "does not have"),
    ):
        _assert_refused(needle, render, TEMPLATE, values)


def _source_list_cases() -> None:
    two = render(SOURCES_TEMPLATE, {"OPERATOR_CIDRS": "192.0.2.7/32,198.51.100.4/32"})
    assert json.loads(two)["cidrs"] == ["192.0.2.7/32", "198.51.100.4/32"]
    one = render(SOURCES_TEMPLATE, {"OPERATOR_CIDRS": "192.0.2.7/32"})
    assert json.loads(one)["cidrs"] == ["192.0.2.7/32"]
    for value, needle in (
        ("0.0.0.0/0", "range"),
        ("192.0.2.7/32,0.0.0.0/0", "range"),
        ("::/0", "range"),
        ("192.0.2.0/24", "range"),
        ("192.0.2.7", "comma-separated addresses in CIDR form"),  # the prefix is always written
        ("192.0.2.7/32,192.0.2.7/32", "distinct"),
        ("192.0.2.7/32;198.51.100.4/32", "comma-separated"),
        ('192.0.2.7/32","0.0.0.0/0', "comma-separated"),
        (",".join(f"192.0.2.{i}/32" for i in range(9)), "at most"),
    ):
        _assert_refused(needle, render, SOURCES_TEMPLATE, {"OPERATOR_CIDRS": value})
    _assert_refused("whole internet", render, "cidrs: [0.0.0.0/0, @@OPERATOR_CIDR@@]\n", OPERATOR)


def _file_contract_cases() -> None:
    """The tracked template is untouched, the output lands in the ignored run directory, is
    never overwritten, and --verify catches an edit made after creation."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / ".gitignore").write_text("/work/\n")
        (repo / "deploy").mkdir()
        tracked = repo / "deploy" / "cluster.yaml"
        tracked.write_text(TEMPLATE)
        before = tracked.read_bytes()
        out = materialize(repo, "deploy/cluster.yaml", "run-1", OPERATOR)
        assert tracked.read_bytes() == before, "the tracked template was modified"
        assert out == repo / "work" / "cloud-runs" / "run-1" / "cluster.yaml"
        assert verify(out).startswith("sha256:")
        assert materialize(repo, "deploy/cluster.yaml", "run-1", OPERATOR) == out
        _assert_refused("never overwritten", materialize, repo, "deploy/cluster.yaml", "run-1",
                        {"OPERATOR_CIDR": "198.51.100.1/32"})
        out.write_text(out.read_text() + "# edited\n")
        _assert_refused("changed since", verify, out)
        (repo / ".gitignore").write_text("")
        _assert_refused("not git-ignored", materialize, repo, "deploy/cluster.yaml", "run-2", OPERATOR)


def selftest() -> int:
    _single_value_cases()
    _source_list_cases()
    _file_contract_cases()
    print("render_cloud_config selftest: OK (template untouched; open-world, unresolved and overwrite refused)")
    return 0
