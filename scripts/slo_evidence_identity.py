#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLO evidence identity — make a performance result content-addressed, twice over.

THE DEFECT. The SLO lane was the only evidence in this repository that was not
content-addressed. `.verification/attestations` are keyed on a fingerprint and are never
re-derived while their inputs are unchanged; `scripts/local_slo_lane.sh` re-measured
unconditionally. An unchanged tree object was therefore asked to prove itself twice, and
the second attempt failed on host contention — costing hours on a release with no code
delta at all.

THE CORRECTION, and why it is two identities rather than one.

A proof result is a theorem about the tree, so `(tree, toolchain)` identifies it completely.
A performance result is not that. It is a claim about a tree RUNNING ON SOMETHING, and the
something drifts underneath an unchanged source tree: kernels, container runtimes, and the
harness's own configuration. Keying a throughput number on the source alone would make an
old number permanently reusable, which is the opposite error to re-measuring every time.

    performance surface   the declared inputs in config/performance-surface.toml — serving
                          source, build configuration, harness, envelope, image definition.
                          A change here INVALIDATES the result.

    measurement context   hardware class, OS class, container-runtime class, CPU count and
                          the benchmark configuration. A different context does not
                          invalidate the old result: it means the old result answers a
                          different question, so this one must be measured.

Reuse requires all three of: same surface, same context, and a record no older than the
declared window. The decision always says which of the three failed, because "re-measure"
with no reason is how unconditional re-measurement comes back.

EVERY DECLARED INPUT MUST BE GIT-TRACKED, and this refuses an untracked one. A fingerprint
input outside the tree makes one commit fingerprint two ways depending on whose working copy
computed it — already a real defect in this repository once.

THE DECLARED HARDWARE CLASSES live here too, in `[[context.class]]`. `hardware_class` is
the context field that decides WHICH QUESTION a number answers, so the vocabulary of legal
values, each class's own regression anchor, and whether a class may ever carry an absolute
production-SLO verdict are declared once and read by every consumer:
`scripts/adr051_slo_gate.py` resolves a report's anchor from it, `scripts/slo_gate.py`
resolves its refusal set from it, and `--runner-class` reports the class the controlled
measurement host (dev1) measures as.

NO CI WORKFLOW RUNS THE SLO. An SLO run is a deliberate measurement made locally on dev1, not a
pull-request, post-merge or release step. "Must this be re-measured?" is answered by CONTENT:
`--decide` folds the declared surface and the measurement context into two digests and compares
them against the attested results in the durable store.

Where the question is asked: `scripts/local_gate.sh` stage 4 calls `--decide` before
measuring, on the machine whose context it describes. `--decide` derives that context from the
host and Docker daemon it runs on, so it answers only where the measurement would run. It is
not a release-qualification input: an SLO result is observational performance evidence, and
release assurance does not consult it.

Run:  python3 scripts/slo_evidence_identity.py                 # validate the declaration
      python3 scripts/slo_evidence_identity.py --emit
      python3 scripts/slo_evidence_identity.py --decide        # 0 = REUSE, 10 = REMEASURE
      python3 scripts/slo_evidence_identity.py --record target/slo-local/rep1.json ...
      python3 scripts/slo_evidence_identity.py --runner-class
      python3 scripts/slo_evidence_identity.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _slo_evidence.check import check  # noqa: E402,F401
from _slo_evidence.classes import (  # noqa: E402,F401
    anchor_consistency_defects,
    class_defects,
    hardware_classes,
    runner_class,
)
from _slo_evidence.cli import run  # noqa: E402
from _slo_evidence.config import (  # noqa: E402,F401
    BASELINE,
    CLASS_KEYS,
    LOCAL_STORE,
    REMEASURE,
    REPO,
    REUSE,
    SCHEMA,
    SECTIONS,
    STORE_ENV,
    SURFACE_TOML,
    TARGETS,
)
from _slo_evidence.context import (  # noqa: E402,F401
    class_environment_digest,
    context_digest,
    measurement_context,
    stale,
)
from _slo_evidence.selftest import selftest  # noqa: E402
from _slo_evidence.store import decide, evidence_store, record, record_path  # noqa: E402,F401
from _slo_evidence.surface import declared_inputs, performance_surface  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return run(__doc__)


if __name__ == "__main__":
    sys.exit(main())
