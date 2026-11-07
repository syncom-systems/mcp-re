# SPDX-License-Identifier: Apache-2.0
"""Validation of an assumption's `sites`: the seams it registers."""

from __future__ import annotations

from _registries import ManifestError
import _tree


def validate_sites(where: str, entry: dict) -> None:
    """`sites` names SEAMS, as `<repo-relative path>#<item>`.

    The path half is checked to exist, because a registration against a file that is not
    there registers nothing while reading as a registration — and the escape-hatch gate,
    which refuses a site key that resolves to no seam, cannot distinguish "the file moved"
    from "the entry was always wrong" once it is only reporting a missing key.

    A duplicate inside one entry is refused too: two identical rows say one thing, and the
    count of registered seams is read.
    """
    declared = entry.get("sites")
    if declared is None:
        return
    _require_nonempty_list(where, declared)
    seen: set[str] = set()
    for site in declared:
        site = str(site)
        path = _site_path(where, site)
        if site in seen:
            raise ManifestError(f"{where}: site {site!r} is registered twice in one entry.")
        seen.add(site)
        _require_site_file(where, site, path)


def _require_nonempty_list(where: str, declared: object) -> None:
    """`sites`, when present, is a list with at least one member."""
    if not isinstance(declared, list) or not declared:
        raise ManifestError(
            f"{where}: `sites` must be a non-empty list. Omit the key entirely to register "
            f"nothing — an EMPTY list and an absent one would be the same fact written two "
            f"ways."
        )


def _require_site_file(where: str, site: str, path: str) -> None:
    """The file half of a site exists in the current tree."""
    if not _tree.current().is_file(path):
        raise ManifestError(
            f"{where}: site {site!r} names {path}, which does not exist. A registration "
            f"against a missing file registers nothing while reading as a registration."
        )


def _site_path(where: str, site: str) -> str:
    """The path half of a `<path>#<item>` site; a site without both halves is refused."""
    path, separator, item = site.partition("#")
    if "" in (path, separator, item):
        raise ManifestError(
            f"{where}: site {site!r} is not `<path>#<item>`. A seam is identified by "
            f"the item it sits on, never by a line number: a line number moves when a "
            f"comment is added above it, and a registry that goes stale on formatting "
            f"is one people regenerate without reading."
        )
    return path
