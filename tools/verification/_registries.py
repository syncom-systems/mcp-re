# SPDX-License-Identifier: Apache-2.0
"""The policy registries: the one reader of `verification/policy/`, and the one check of
the rule that keeps it the one reader.

THE FAILURE CLASS. The registries name each other. A mutation probe names a unit, a
theorem, a file and the text it weakens. A theorem names the units that support it. An
assumption names the units and boundaries it is scoped to and the seams it trusts. A
control disposition names a proposition. Each registry was opened raw by whichever tool
needed it, and each reference was checked late, by whichever lane happened to look: a
probe's anchor only by a suite asserting over live data, which checked the first site and
not the `also` sites; an assumption's site only by the assumptions lane, behind a path
filter; a disposition id by nothing, so eight ids were taken twice by parallel changes. A
registry edit therefore came with a remembered rule: run every suite.

So reading is owned once. `parse`, `read`, `document`, `rows`, `text`, `text_at` and
`blob_at` are the only code that turns a policy registry's bytes into data. The typed
loaders (`_manifest.load_verification`, `_theorems.load_theorems`, `_mutation.load_probes`,
`_structural.load_probes`, `_measured.load_measurements`, `_toolchains.load`) read through
them and add their own schema, and `reader_problems` refuses a reader around this module.
The same rule holds each generated table in `GENERATED_OWNERS` to the module that reads it.
The references between registries are checked by `_registry_refs`, which sits above the
typed loaders; `check-registries` runs both on the merge path.

Stdlib only, and it imports nothing from this package outside the `_registries_*` modules it
is assembled from: every typed loader imports it.
"""

from __future__ import annotations

from _registries_reader_rule import GENERATED_OWNERS, reader_problems, source_problems
from _registries_reading import (
    GUARDED,
    POLICY_DIR,
    POLICY_RELATIVE,
    REGISTRIES,
    REPO_ROOT,
    ManifestError,
    blob_at,
    document,
    duplicate_ids,
    parse,
    path,
    policy_files,
    read,
    relative,
    rows,
    text,
    text_at,
)

__all__ = [
    "GENERATED_OWNERS",
    "GUARDED",
    "ManifestError",
    "POLICY_DIR",
    "POLICY_RELATIVE",
    "REGISTRIES",
    "REPO_ROOT",
    "blob_at",
    "document",
    "duplicate_ids",
    "parse",
    "path",
    "policy_files",
    "read",
    "reader_problems",
    "relative",
    "rows",
    "source_problems",
    "text",
    "text_at",
]
