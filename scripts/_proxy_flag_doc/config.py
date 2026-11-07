# SPDX-License-Identifier: Apache-2.0
"""What the gate scans, which parsers it reads, and the floors the scan must clear."""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

REPO = Path(__file__).resolve().parent.parent.parent

CLI_MODULE = "mcp-re-proxy/src/cli.rs"

# Flag literals also live in `cli.rs`'s own child modules: a family parsed behind one
# delegating arm states its spellings there, and a gate reading only `cli.rs` would report
# every one of those flags as non-existent. The set is the parser, wherever the parser is.
CLI_MODULE_DIR = "mcp-re-proxy/src/cli"

AUDITOR_MODULE = "mcp-re-proxy/src/transparency/auditor/invocation/mod.rs"

# Documentation roots. `docs/archive/` is history by definition and records the surface as
# it was; `docs/security/round-*/` holds captured gate logs, not instructions.
#
# Repo-root markdown is in scope too: README.md and CONTRIBUTING.md are the first
# documents an operator reads, and a scan that stops at `docs/` would never see a command
# line in either.
DOC_ROOTS = ("docs", "deploy")
SKIP_PARTS = ("archive", "grilling-seed")
SKIP_PATTERNS = (re.compile(r"docs/security/round-"),)

# Floors on what the scan actually selected. A gate whose document set collapses to zero
# reports the same green as one that examined everything, so the size of the set is part
# of what has to hold. Each tool's `min_launch_docs` is the load-bearing one: markdown
# files exist in quantity, documents that actually LAUNCH a tool are the population under
# test.
MIN_SCANNED_DOCS = 40

# A fenced block: ```[lang]\n ... \n```
FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)


# The proxy is being LAUNCHED, as opposed to merely named. Two spellings reach it: the
# Bazel target / built binary `mcp_re_proxy_cli`, and the installed `mcp-re-proxy` binary
# at the head of a command. Everything after that token — past an optional `--` separator
# — is the proxy's own argv. Anchoring on the invocation rather than on the block keeps
# `helm --set`, `kubectl`, `gcloud` and `cargo test -- --nocapture` out, all of which
# appear in blocks that also mention the proxy.
def launches(target: str, binary: str) -> re.Pattern[str]:
    return re.compile(
        r"(?:"
        # The Bazel target or the built CLI, wherever it appears in the command.
        rf"[\w./${{}}-]*{re.escape(target)}"
        # The installed binary, only as the command being run. Anywhere else it is a crate
        # name (`cargo test -p mcp-re-proxy`), a chart name (`helm upgrade mcp-re-proxy`)
        # or a directory, and the flags around it are some other tool's.
        rf"|^\s*(?:\$\s+)?(?:[A-Z_][A-Z0-9_]*=\S+\s+)*(?:\./|/\S*/)?{re.escape(binary)}"
        r")(?:\s+--(?=\s)|)(?=\s)"
    )


class Tool(NamedTuple):
    """One executable, its parser, and the floor its documentation must clear."""

    binary: str
    target: str
    #: Files whose `"--flag"` literals ARE this tool's accepted set.
    sources: tuple[str, ...]
    #: Directories every `*.rs` of which is also part of the parser.
    source_dirs: tuple[str, ...]
    #: Below this many literals the gate is no longer reading the parser it thinks it is.
    min_flags: int
    #: A tool nothing documents is a tool whose guide silently left the scan.
    min_launch_docs: int

    def launch_pattern(self) -> re.Pattern[str]:
        return launches(self.target, self.binary)


TOOLS = (
    Tool("mcp-re-proxy", "mcp_re_proxy_cli", (CLI_MODULE,), (CLI_MODULE_DIR,), 20, 2),
    # The auditor's parser is one file and its surface is deliberately small: nine flags,
    # every one required except the audit instant. The floor is set below that so a flag
    # being removed is a gate failure rather than a floor failure.
    Tool("mcp-re-auditor", "mcp_re_auditor_cli", (AUDITOR_MODULE,), (), 8, 1),
)

# `--flag` but not `--` alone and not a `--flag=` fragment inside a URL.
FLAG = re.compile(r"(?<![\w=/-])(--[a-z0-9][a-z0-9-]*)")

# Every `"--flag"` string literal in cli.rs. The parser matches on these, so their
# presence is exactly the question "does this flag exist".
CLI_FLAG_LITERAL = re.compile(r'"(--[a-z0-9][a-z0-9-]*)"')

# `bazel run //target:mcp_re_proxy_cli --features x -- --bind y` puts the launcher's own
# flags AFTER the target name and before the `--`, so anchoring on the invocation is not
# enough to exclude them. Kept to flags Bazel and Cargo actually take in that position —
# every entry here is a hole in the check, so speculative ones do not belong.
LAUNCHER_FLAGS = frozenset(
    {
        "--features",
        "--release",
        "--config",
        "--compilation_mode",
        "--test_output",
    }
)

# A document that opens by declaring itself superseded is describing a surface that is
# gone ON PURPOSE, and its command lines are the evidence for that claim.
#
# The banner alone does not grant the exemption. A check a document can opt out of by
# writing one line about itself is a check any live operator guide can silence, so the
# exemption is held HERE, by path, and the banner and the entry must agree:
#
#   listed + banner   -> skipped, and reported
#   banner, unlisted  -> FAIL; the document is claiming an exemption the gate did not give
#   listed, no banner -> FAIL; the entry outlived the document's own claim about itself
SUPERSEDED = re.compile(r"^>\s*\*\*[⚠!]?\s*Superseded", re.M)

SUPERSEDED_DOCS = frozenset(
    {
        "docs/dogfood-runbook.md",
        "docs/spec/v0.3-claim-matrix.md",
    }
)
