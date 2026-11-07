# SPDX-License-Identifier: Apache-2.0
"""The selftest's documents: each is (name, markdown, should pass, path in the fixture)."""

from __future__ import annotations

DEFAULT_PATH = "docs/case.md"

SUPERSEDED_BANNER = "> **⚠ Superseded serving model.**\n\n"

#: Cases about the per-document logic, each written to a path of its own choosing.
DOCUMENT_CASES: tuple[tuple[str, str, bool, str], ...] = (
    (
        "a proxy block using a known flag passes",
        "```sh\nmcp_re_proxy_cli --bind 127.0.0.1:8600\n```\n",
        True,
        DEFAULT_PATH,
    ),
    (
        "a proxy block using an unknown flag fails",
        "```sh\nmcp_re_proxy_cli --bind 127.0.0.1:8600 --gone-flag x\n```\n",
        False,
        DEFAULT_PATH,
    ),
    (
        "prose naming a removed flag is not scanned",
        "The `--gone-flag` option was removed in v0.13.\n",
        True,
        DEFAULT_PATH,
    ),
    (
        "a block that does not invoke the proxy is not scanned",
        "```sh\ngcloud container clusters create c --num-nodes 3 --gone-flag x\n```\n",
        True,
        DEFAULT_PATH,
    ),
    (
        "launcher flags before the `--` separator are not the proxy's",
        "```sh\nbazel run //mcp-re-proxy:mcp_re_proxy_cli --features x -- --bind y\n```\n",
        True,
        DEFAULT_PATH,
    ),
    (
        "an UNLISTED document cannot exempt itself with a Superseded banner",
        SUPERSEDED_BANNER + "```sh\nmcp_re_proxy_cli --gone-flag x\n```\n",
        False,
        DEFAULT_PATH,
    ),
    (
        "the crate name in a cargo command is not an invocation",
        "```sh\ncargo test -p mcp-re-proxy --gone-flag x\n```\n",
        True,
        DEFAULT_PATH,
    ),
    (
        "repo-root markdown is scanned",
        "```sh\nmcp_re_proxy_cli --gone-flag x\n```\n",
        False,
        "README.md",
    ),
    (
        "an auditor block using a known auditor flag passes",
        "```sh\nmcp-re-auditor --retained-evidence-dir /archive --hop abc\n```\n",
        True,
        DEFAULT_PATH,
    ),
    (
        "an auditor block using an unknown flag fails",
        "```sh\nmcp-re-auditor --retained-evidence-dir /archive --gone-flag x\n```\n",
        False,
        DEFAULT_PATH,
    ),
    # The point of checking each tool against its OWN parser: `--bind` exists, and
    # the auditor does not take it. A gate that pooled the two vocabularies would
    # report this command line — which does not run — as green.
    (
        "a proxy flag in an auditor command line fails",
        "```sh\nmcp-re-auditor --bind 127.0.0.1:8600\n```\n",
        False,
        DEFAULT_PATH,
    ),
    (
        "an auditor flag in a proxy command line fails",
        "```sh\nmcp_re_proxy_cli --retained-evidence-dir /archive\n```\n",
        False,
        DEFAULT_PATH,
    ),
)

#: A LISTED document with the banner is skipped; the same document without the banner is
#: scanned again and its stale entry reported. Written at the first SUPERSEDED_DOCS path.
LISTED_CASES: tuple[tuple[str, str, bool], ...] = (
    (
        "a listed document declaring itself superseded is skipped",
        SUPERSEDED_BANNER + "```sh\nmcp_re_proxy_cli --gone-flag x\n```\n",
        True,
    ),
    (
        "a listed document that dropped its banner is reported, not skipped",
        "```sh\nmcp_re_proxy_cli --bind 127.0.0.1:8600\n```\n",
        False,
    ),
)
