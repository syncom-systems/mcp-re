# SPDX-License-Identifier: Apache-2.0
"""Reading the production source the claims are about, and the gate's whole verdict over a tree."""

from __future__ import annotations

from pathlib import Path

from _rust_source import crate_sources, production_view

from _authorization_provenance.authority import check_authority
from _authorization_provenance.config import AUTHORITY_DIR, PLANE, REPO, SERVING, STAGES, VALIDATION
from _authorization_provenance.dispatch import check_dispatch, check_validation
from _authorization_provenance.rusttext import without_comments
from _authorization_provenance.serving import check_serving


class Anchored(str):
    """Source text whose `replace` refuses to be a no-op.

    A selftest case mutates live source by replacing a literal. When the source moves and
    the literal no longer occurs, `str.replace` returns the text unchanged and the case
    reports a confusing "0 problem(s)" against an unmutated tree, or, for a case expecting
    none, passes without having tested anything. Requiring the anchor makes that a named
    failure that says which literal to re-point.
    """

    def replace(self, old, new, *args):
        if old not in self:
            raise SystemExit(
                f"selftest anchor not found in the live source: {old!r}. The source moved; "
                f"re-point this case at the text that now makes the same claim."
            )
        return Anchored(super().replace(old, new, *args))


def authority_sources(directory: Path) -> dict[str, str]:
    """Every production `.rs` file of the authority, keyed by its RELATIVE PATH.

    Keyed by path, not by file name: `authorization/mod.rs` and `authorization/pdp/mod.rs`
    share a name, and a name-keyed dict silently drops one of them — a gate that examines
    less than it claims to, which is the failure mode that matters most in a gate.
    """
    return {
        str(p.relative_to(REPO)): Anchored(production_view(p).text())
        for p in crate_sources(directory)
    }


def read(repo: Path, rel: str) -> str:
    """One unit's production source: a file, or an owner subtree read whole.

    Each member's production half is taken SEPARATELY before joining — concatenating first
    would let one file's unterminated test region swallow the next file's production code,
    and the exactly-once counts are precisely what that would corrupt.
    """
    target = repo / rel
    if target.is_file():
        return Anchored(production_view(target).without_comments())
    members = crate_sources(target)
    if not members:
        raise SystemExit(f"{rel}: a serving path with no Rust source is not measurable")
    return Anchored("\n".join(
        production_view(m).without_comments() for m in members
    ))


def check(repo: Path) -> tuple[list[str], int]:
    directory = repo / AUTHORITY_DIR
    sources = authority_sources(directory)
    serving = read(repo, SERVING)
    problems = check_authority(sources)
    problems += check_serving(serving)
    problems += check_dispatch(
        read(repo, STAGES),
        without_comments("\n".join(sources.values())),
        serving,
        read(repo, PLANE),
    )
    problems += check_validation(read(repo, VALIDATION))
    return problems, len(sources)
