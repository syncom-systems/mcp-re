# SPDX-License-Identifier: Apache-2.0
"""The command line: render, or `--verify` a rendered file."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from _cloud_render.check import Refused
from _cloud_render.files import materialize, verify


@dataclass
class Request:
    template: str | None = None
    run_id: str | None = None
    values: dict[str, str] = field(default_factory=dict)


def _set_value(assignment: str, values: dict[str, str]) -> None:
    name, sep, value = assignment.partition("=")
    if not sep:
        raise Refused("--set takes NAME=VALUE")
    values[name] = value


def _consume(arg: str, rest, request: Request) -> None:
    if arg == "--template":
        request.template = next(rest)
    elif arg == "--run-id":
        request.run_id = next(rest)
    elif arg == "--set":
        _set_value(next(rest), request.values)
    else:
        raise Refused(f"unknown argument {arg!r}")


def parse_request(argv: list[str]) -> Request:
    request = Request()
    rest = iter(argv)
    for arg in rest:
        _consume(arg, rest, request)
    if not request.template or not request.run_id:
        raise Refused("--template and --run-id are required")
    return request


def run(argv: list[str], repo: Path) -> int:
    try:
        if argv[:1] == ["--verify"] and len(argv) == 2:
            print(f"verified: {argv[1]} {verify(Path(argv[1]))}")
            return 0
        request = parse_request(argv)
        out = materialize(repo, str(request.template), str(request.run_id), request.values)
        print(out.relative_to(repo))
        return 0
    except (Refused, StopIteration, FileNotFoundError) as exc:
        print(f"render_cloud_config: REFUSED — {exc}", file=sys.stderr)
        return 1
