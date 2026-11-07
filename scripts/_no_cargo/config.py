# SPDX-License-Identifier: Apache-2.0
"""What the gate reads and what it counts as a Cargo invocation: the rule tables and their constants."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

#: One finding: (line, rule, text). Line 0 means the file as a whole.
Hit = tuple[int, str, str]

#: Directories and files that record history rather than state a command to run.
HISTORY = (
    "docs/archive/",
    "docs/security/",
    "docs/adr/",
    "docs/releases/",
    "docs/bench/",
    "verification/reviews/",
    "verification/claim-corrections/",
    "work/",
    "CHANGELOG.md",
)

#: The documents whose fenced shell blocks are maintained commands someone — or an agent —
#: is told to run.
COMMAND_DOCS = re.compile(
    r"^(?:CLAUDE\.md|AGENTS\.md|CONTRIBUTING\.md|README\.md|[^/]+/README\.md|sdk/[^/]+/README\.md"
    r"|deploy/.+/README\.md|docs/[^/]+\.md|docs/dev/.+\.md|tools/[^/]+/README\.md|tools/verification/README\.md"
    r"|verification/README\.md|verification/[^/]+/README\.md|\.claude/.+\.md)$"
)

CARGO_BIN = r"cargo(?:-[a-z][a-z0-9-]*)?"
#: A shell command word position: line start, or after a separator, a subshell or a prefix
#: that runs its argument (`env`, `exec`, `time`, `timeout N`, `xargs`, `sudo`, a
#: `VAR=value` assignment).
_PREFIX = r"(?:(?:env|exec|time|nice|sudo|xargs(?:\s+-\S+)*|timeout\s+\S+|[A-Z_][A-Z0-9_]*=\S*)\s+)*"
_POSITION = r"(?:^\s*(?:RUN\s+)?|[;&|(`]|\$\(|\bthen\b|\bdo\b|\belse\b|\{)\s*" + _PREFIX
SHELL_RULES = (
    ("cargo", re.compile(_POSITION + r"(?:[^\s=]*/)?" + CARGO_BIN + r"(?=\s|$|[;&|)`])")),
    ("rustup run … cargo", re.compile(r"\brustup\s+run\s+\S+\s+" + CARGO_BIN + r"\b")),
    ("$CARGO", re.compile(_POSITION + r"[\"']?\$\{?CARGO(?:[:}][^\s\"']*)?[\"']?(?=\s)")),
    ("napi build", re.compile(r"\bnapi\s+build\b")),
    ("maturin", re.compile(_POSITION + r"maturin\s+(?:build|develop|publish)\b")),
    ("charon cargo", re.compile(r"\bcharon\S*\s+cargo\b", re.IGNORECASE)),
    ("cross", re.compile(_POSITION + r"cross\s+(?:build|test|run)\b")),
)
PRINTS = re.compile(r"^\s*(?:-\s*)?(?:echo|printf)\b")
FENCE = re.compile(r"^\s*(```|~~~)\s*([A-Za-z]*)")
SHELL_LANGS = {"", "sh", "bash", "shell", "console", "zsh"}
ARGV_KEYS = ("protocol", "control", "argv", "command")
INLINE = re.compile(r"`([^`\n]+)`")

#: Actions that drive Cargo for a step.
CARGO_ACTION = re.compile(
    r"^(?:EmbarkStudios/cargo-deny-action|actions-rs/cargo|PyO3/maturin-action|messense/maturin-action)(?:@|$)"
)

#: The calls that run a command line through a shell.
SPAWNS = {"run", "call", "check_call", "check_output", "Popen", "system", "popen",
          "getoutput", "getstatusoutput"}

#: A Cargo command at the start of a line of a Python file — a docstring or comment telling a
#: maintainer to run it. Mid-sentence mentions and quoted fixtures do not start a line.
PY_CARGO_COMMAND_LINE = re.compile(
    r"^\s*(?:#\s*|\$\s*)?(?:[A-Z_]+=\S+\s+)*cargo\s+(?:test|run|build|check|clippy|fmt|bench|doc|tree|"
    r"metadata|install|publish|verus)\b"
)

#: A Cargo subcommand written as a command line. In a Rust file this is read in COMMENTS too: a
#: doc comment's `cargo test -p x` is the command a maintainer is told to run.
RUST_CARGO_COMMAND = re.compile(
    r"\bcargo\s+(?:test|run|build|check|clippy|fmt|bench|doc|tree|metadata|install|publish|verus)\b"
)

#: `Command::new` of the cargo binary, by literal path or by the environment's `CARGO`.
RUST_COMMAND_NEW = re.compile(
    r'Command::new\(\s*(?:"(?:\S*/)?cargo"|env!\(\s*"CARGO"\s*\)|&?(?:std::)?env::var\(\s*"CARGO"\s*\))'
)

#: A JavaScript/TypeScript spawn of cargo, napi or maturin.
JS_SPAWN = re.compile(
    r"""(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\(\s*['"`](?:cargo|napi\s+build|maturin)\b"""
)
