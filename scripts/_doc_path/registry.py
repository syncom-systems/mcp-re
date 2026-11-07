# SPDX-License-Identifier: Apache-2.0
"""The doc-path debt register: its schema, its loading and its emission."""

from __future__ import annotations

from pathlib import Path

import _ratchet

from _doc_path.config import REGISTRY, REPO

#: The register's shape. `_ratchet` checks it, the `review_ref` rule included;
#: `load_registry` adds the one field rule that is this registry's own.
SCHEMA = _ratchet.Schema(
    table="debt",
    key="path",
    required=frozenset({"path", "dead_tokens", "status"}),
    fields=frozenset({"path", "dead_tokens", "status", "review_ref"}),
    statuses=("unreviewed", "reviewed-action-required", "reviewed-exception"),
    reviewed=frozenset({"reviewed-action-required", "reviewed-exception"}),
)


def load_registry(path: Path, root: Path = REPO) -> tuple[dict[str, dict], list[str]]:
    """The register at `path` under `root`, and every way it departs from its schema.

    An absent register is a failure here, not an empty one: this gate's register is the
    whole of its baseline, so with no file there is nothing it could have compared.
    """
    register = _ratchet.Register(path.relative_to(root).as_posix(), SCHEMA, root)
    if not register.exists():
        return {}, [f"{path} does not exist"]
    try:
        rows = register.current()
    except _ratchet.RegisterError as exc:
        return {}, [str(exc)]
    errors = register.problems(rows) + [
        f"{rel}: unreviewed rows carry no review_ref"
        for rel, row in sorted(rows.items())
        if row.get("status") == "unreviewed" and "review_ref" in row
    ]
    return rows, errors


def emit_registry(measured: dict[str, list[str]]) -> str:
    head = (REGISTRY.read_text().split("[[debt]]")[0] if REGISTRY.exists() else "")
    body = []
    for rel, hits in sorted(measured.items()):
        body.append(
            "[[debt]]\n"
            f'path = "{rel}"\n'
            f"dead_tokens = {len(hits)}\n"
            'status = "unreviewed"\n'
        )
    return head + "\n".join(body)
