# SPDX-License-Identifier: Apache-2.0
"""Cargo invocations in Rust, JavaScript/TypeScript and TOML registries."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterator

from _no_cargo.config import (
    ARGV_KEYS,
    JS_SPAWN,
    RUST_CARGO_COMMAND,
    RUST_COMMAND_NEW,
    Hit,
)
from _no_cargo.shell import is_cargo_word


def _code_lines(text: str) -> Iterator[tuple[int, str]]:
    """Numbered lines that are not `//` comments."""
    for n, line in enumerate(text.splitlines(), 1):
        if not line.lstrip().startswith("//"):
            yield n, line


def rust_hits(text: str) -> list[Hit]:
    out = [(n, "Command::new(cargo)", line.strip())
           for n, line in _code_lines(text) if RUST_COMMAND_NEW.search(line)]
    out += [(n, "cargo command in a comment or string", line.strip())
            for n, line in enumerate(text.splitlines(), 1) if RUST_CARGO_COMMAND.search(line)]
    return out


def js_hits(text: str) -> list[Hit]:
    return [(n, "spawn cargo", line.strip())
            for n, line in _code_lines(text) if JS_SPAWN.search(line)]


def _argv_items(key: object, item: object) -> list | None:
    """The elements of a registry value that is a non-empty argv array under an argv key."""
    if key not in ARGV_KEYS or not isinstance(item, list):
        return None
    return item or None


def _cargo_argv_text(key: object, item: object) -> str | None:
    """The command line of a registry value that is an argv array starting with cargo."""
    argv = _argv_items(key, item)
    if argv is None or not isinstance(argv[0], str):
        return None
    return " ".join(map(str, argv))[:120] if is_cargo_word(argv[0]) else None


def _argv_hit(key: object, item: object) -> Iterator[Hit]:
    text = _cargo_argv_text(key, item)
    if text is not None:
        yield (0, f"cargo argv in `{key}`", text)


def _walk_dict(table: dict) -> Iterator[Hit]:
    for key, item in table.items():
        yield from _argv_hit(key, item)
        yield from _walk_toml(item)


def _walk_list(items: list) -> Iterator[Hit]:
    for item in items:
        yield from _walk_toml(item)


def _walk_toml(value: object) -> Iterator[Hit]:
    if isinstance(value, dict):
        yield from _walk_dict(value)
    elif isinstance(value, list):
        yield from _walk_list(value)


def toml_hits(text: str) -> list[Hit]:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    out = list(_walk_toml(doc))
    if re.search(r'build-backend\s*=\s*"maturin"', text):
        out.append((0, "maturin build backend", "build-backend = \"maturin\""))
    return out
