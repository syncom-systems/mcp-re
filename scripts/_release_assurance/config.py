# SPDX-License-Identifier: Apache-2.0
"""The canonical command, the workflow that must call it, and how each release document is backed."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

#: The one authority a release procedure may call. Not a family, not a prefix.
CANONICAL = "tools/verification/release-assurance"

#: The workflow that must call it.
WORKFLOW = Path(".github/workflows/release.yml")

#: The only workflow ref a NEW committed record may have been produced by.
PRODUCER_REF_SUFFIX = f"/{WORKFLOW}@refs/heads/main"

#: The workflow path before the 2026-10-17 rename to `release.yml`. A record committed before
#: then names it, and GitHub attested that run under that path, so the record cannot be
#: rewritten. It is accepted ONLY for the documents listed in `LEGACY_PRODUCED`: an enumerated
#: exception, not a second producer. The file is gone from `main`, and `--verify-run` accepts
#: only `WORKFLOW`, so no new run can be produced under it.
LEGACY_WORKFLOW = Path(".github/workflows/release-assurance.yml")
LEGACY_PRODUCER_REF_SUFFIX = f"/{LEGACY_WORKFLOW}@refs/heads/main"
LEGACY_PRODUCED = frozenset({"v0.18.0-provenance.md"})

#: Where release provenance documents live.
RELEASES = Path("docs/releases")

#: How each provenance document's assurance claim is backed. The registry may only shrink
#: in the `pre-mechanism` direction: a historical document is a DATED measurement and is not
#: retroactively falsified by a mechanism that did not exist when it was written — but a new
#: one may not join that class, and an unregistered document is refused outright.
#:
#: `mechanized` — the document carries a `release-assurance` marker block whose commit and
#:               verdict must equal the record COMMITTED beside it, at
#:               `docs/releases/<version>-release-assurance.json`. The record is tracked
#:               rather than left as a CI artifact on purpose: a document checked against a
#:               file that expires in 90 days is a document that stops being checked, and
#:               `.verification/` is gitignored, so a gate reading there would pass on every
#:               fresh checkout by finding nothing.
#: `pre-mechanism` — written before the command existed; the reason is recorded and the
#:               document is not checked for correspondence.
BACKING: dict[str, str] = {
    "v0.16.0-provenance.md": "pre-mechanism",
    "v0.17.0-provenance.md": "pre-mechanism",
    "v0.18.0-provenance.md": "mechanized",
    "v0.19.0-provenance.md": "mechanized",
    "v0.18.1-provenance.md": "mechanized",
}

#: The block a `mechanized` document carries, rendered from the record and never typed.
MARKER_BEGIN = "<!-- release-assurance:begin -->"
MARKER_END = "<!-- release-assurance:end -->"
