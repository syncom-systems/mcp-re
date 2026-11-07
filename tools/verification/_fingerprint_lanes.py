# SPDX-License-Identifier: Apache-2.0
"""The instruments each lane measures with — the lane-identity components of a fingerprint.

Each tuple names the code that decides what a lane's evidence MEANS, and each identity
function digests it for the units that claim the lane. Evidence whose instrument changed is
evidence whose meaning changed, so these bytes belong in the unit's fingerprint.

`_fingerprint.py` is deliberately NOT in any tuple. Its identity is carried by
`ENCODING_VERSION`, which is what a change of MEANING there must move; hashing the file
would additionally invalidate every unit for a comment.
"""

from __future__ import annotations

from _fingerprint_digest import digest_paths
from _lanes import claims

#: The code that decides WHICH tests a selector names and WHERE they run. Not a build
#: input — a measurement instrument, and evidence whose instrument changed is evidence
#: whose meaning changed.
TEST_LANE_INPUTS = (
    "tools/verification/verify-tests",
    "tools/verification/_manifest.py",
    # The admission primitives every unit record passes through: which keys it may carry,
    # which it must, and the one read of the registry from the source tree.
    "tools/verification/_record_rules.py",
    # The adapter registry: which ecosystem a path belongs to, which project runs the
    # battery, and how a selected result is read. It decides what a symbol NAMES, so a
    # change to it changes what the recorded evidence means — the same argument that put
    # the lane itself here (issue #745).
    "tools/verification/_ecosystems.py",
    # What a Rust label resolves to — its crate root, sources and features — is read from
    # the build-graph table through this module.
    "tools/verification/_rust_targets.py",
    # Which units the lane covers: the scheme that claims it and the tiers it applies to are
    # read from the lane catalogue.
    "tools/verification/_lanes.py",
)


def _claimed_identity(unit: dict, scheme: str, inputs: tuple[str, ...]) -> dict[str, str]:
    """The digest of a lane's instrument, empty for a unit that does not claim the lane."""
    if not claims(unit, scheme):
        return {}
    return digest_paths(list(inputs))


def test_lane_identity(unit: dict) -> dict[str, str]:
    return _claimed_identity(unit, "test", TEST_LANE_INPUTS)


#: The lane that decides what "a declared control went red" means.
MUTATION_LANE_INPUTS = (
    "tools/verification/verify-mutations",
    # The registry's schema and what a probe's sites resolve to: whether an anchor is STALE
    # is decided here, before the lane weakens anything.
    "tools/verification/_mutation.py",
    # What a probe's `expect_red` label RUNS: the label is resolved to its crate root and
    # features through the build-graph table, and the ecosystem adapter builds the argv and
    # reads the result. Either one changing changes what a recorded red means.
    "tools/verification/_rust_targets.py",
    "tools/verification/_ecosystems.py",
    # Which units the lane covers: the scheme that claims it and the tiers it applies to are
    # read from the lane catalogue.
    "tools/verification/_lanes.py",
)


def mutation_lane_identity(unit: dict) -> dict[str, str]:
    return _claimed_identity(unit, "mutation", MUTATION_LANE_INPUTS)


#: The lane that decides what a machine-checked PROOF is, and whether one was checked.
#:
#: Two files, and the criterion for membership is *can changing this alter whether the lane
#: reports valid Verus evidence, what proved-symbol population was activated, or whether a
#: zero/non-activated run is accepted?* — not *is it imported*. `verify-verus` imports
#: `_evidence`, `_manifest` and this module and none of them is here on that account.
#:
#: `toolchain_identity` does NOT cover this. It pins the prover's INPUTS — `vstd.vir`,
#: `libvstd.rlib`, the `verus.binaries` executables, the solver. These two are the code that
#: COMPARES those pins, sets `VERUS_Z3_PATH` from the lock, refuses a `focus` run, and
#: decides between NOT_REQUIRED, SKIPPED, PASS and FAIL. Pinning an instrument's inputs is
#: not pinning the instrument, and this lane's own history is a record of that check being
#: strengthened: the digest set was once `vstd.vir` and the commit alone, and a substituted
#: `rust_verify` shipping the pinned vstd passed both.
VERUS_LANE_INPUTS = (
    "tools/verification/verify-verus",
    # The adjudicator, separately: it reads the prover's own JSON report and decides whether
    # the unit's evidence EXISTS — prover identity as reported, whole-crate verification
    # rather than a partial run, and whether the named theorems were processed. Same
    # position `_structural.py` holds for the structural lane and `_measured.py` for the
    # measured one, and both of those are lane inputs already.
    "tools/verification/_verus_results.py",
    # Which crate is verified for a unit: the `verus_verify` target is chosen by the PACKAGE
    # the build-graph table files it under. A filing change re-points a unit at another
    # target's run without touching the runner.
    "tools/verification/_rust_targets.py",
    # Whether the artifact verifiers' postconditions constrain at all: the lane refuses unless
    # the probe's negatives fail, and that adjudication lives here.
    "tools/verification/_verus_nonvacuity.py",
    # Which units the lane covers: the scheme that claims it and the tiers it applies to are
    # read from the lane catalogue.
    "tools/verification/_lanes.py",
)

#: The lane that decides what "the compiler refused the hostile construction" means.
STRUCTURAL_LANE_INPUTS = (
    "tools/verification/verify-structural",
    # The adjudicator, separately: it decides whether a refusal is ATTRIBUTABLE to the
    # boundary the probe attacks, and a change there changes what every structural record
    # means without touching the runner.
    "tools/verification/_structural.py",
    # Which units the lane covers: the scheme that claims it and the tiers it applies to are
    # read from the lane catalogue.
    "tools/verification/_lanes.py",
)

#: The lane that decides what "the apparatus can still MOVE" means.
MEASURED_LANE_INPUTS = (
    "tools/verification/verify-measured",
    "tools/verification/_measured.py",
    # Which units the lane covers: the scheme that claims it and the tiers it applies to are
    # read from the lane catalogue.
    "tools/verification/_lanes.py",
)


#: The lane that decides what "the extracted-model theorem STANDS" means.
#:
#: The judgement cone, not the import closure — `verify-lean` transitively imports fourteen
#: modules and most of them decide nothing about the verdict. Each entry answers yes to one
#: question: can changing this file alter whether the lane reports valid Lean evidence, what
#: theorem population was activated, or whether a run that elaborated nothing is accepted?
LEAN_LANE_INPUTS = (
    # The runner: which units are in scope, what PASS / FAIL / UNAVAILABLE mean, and when a
    # record is written at all — including the `external_termination` path that deliberately
    # writes NONE.
    "tools/verification/verify-lean",
    # What "the theorem stands" means: the kernel baseline, which axioms are permissible,
    # and what a registered premise excuses. Softening it widens every standing PASS without
    # touching a theorem.
    "tools/verification/_lean_axioms.py",
    # What "asking the prover" is: elaboration, the `lake` invocation, and the rule that
    # decides whether a non-zero exit is evidence or an OOM kill.
    "tools/verification/_lean_query.py",
    # Whether the model the theorems were elaborated against corresponds to this tree, and
    # (since the stamp split) whether an observation is a FAIL or an UNAVAILABLE.
    "tools/verification/_lean_model.py",
    # Whether the pinned image IS a build of the toolchain the tree declares.
    # `toolchain_identity` digests the recorded pins; this decides whether the record is an
    # identity at all, which is the check that was one-directional until issue #541.
    "tools/verification/_extraction_identity.py",
    # `selection(doc)` — which symbols and theorems the lane is asked about — and the V2/V3
    # class rules. It rides in on `test_lane_identity` today only because the one lean unit
    # ALSO claims `test://`; a lean-only unit would have it measured by nobody.
    "tools/verification/_manifest.py",
    # The admission primitives under that loader and under the premise registry's.
    "tools/verification/_record_rules.py",
    # The V2/V3 class rules `selection(doc)` rests on: which selection keys a class must
    # declare and that its evidence says so.
    "tools/verification/_unit_rules.py",
    # Which premises the registry admits: a registered premise is what excuses an axiom, so
    # a loader that admits a malformed one widens what the lane accepts.
    "tools/verification/_assumptions.py",
    # Whether a tool the lane needs is pinned at all: an unpinned or absent identity makes
    # the run UNAVAILABLE rather than a verdict.
    "tools/verification/_toolchain_lock.py",
    # Which units the lane covers: the scheme that claims it and the tiers it applies to are
    # read from the lane catalogue.
    "tools/verification/_lanes.py",
)

#: `_lean_probe.py` is deliberately NOT above, and the reason is the criterion rather than
#: the topic. The probe runs only under `verify-lean --activation-probe`, which returns
#: before any unit is looked at, writes no evidence record and names nothing the manifest
#: declares. So changing it cannot alter whether the lane reports valid Lean evidence, which
#: theorems were activated, or whether a run that elaborated nothing is accepted — it can
#: only weaken the separate proof that the lane's refusals still fire. That is a control ON
#: the lane, gated by its own CI step, not part of what a `lean` record MEANS. The two files
#: it depends on to make its judgement, `_lean_axioms.py` and `_lean_query.py`, are in the
#: cone above, so excluding the probe drops no judging code.

#: The lane that decides what "the committed model IS the model this tree extracts" means.
GENERATED_MODEL_LANE_INPUTS = (
    "tools/verification/check-generated",
    # How the model is DERIVED from source. The pinned Charon and Aeneas are in
    # `toolchain_identity`; the invocation is not, and it decides what the model means
    # relative to the Rust it came from.
    "tools/verification/regenerate-lean",
    "tools/verification/_lean_model.py",
    "tools/verification/_extraction_identity.py",
    # Which units the lane covers: the scheme that claims it and the tiers it applies to are
    # read from the lane catalogue.
    "tools/verification/_lanes.py",
)


#: Unlike the lane identities above, the two below carry no `claims` guard: the caller adds
#: them to the component map only where the unit declares the scheme, so an empty return
#: would be an unreachable second answer to a question the call site has already asked.
def lean_lane_identity() -> dict[str, str]:
    return digest_paths(list(LEAN_LANE_INPUTS))


def generated_model_lane_identity() -> dict[str, str]:
    return digest_paths(list(GENERATED_MODEL_LANE_INPUTS))


def verus_lane_identity(unit: dict) -> dict[str, str]:
    return _claimed_identity(unit, "verus", VERUS_LANE_INPUTS)


def structural_lane_identity(unit: dict) -> dict[str, str]:
    return _claimed_identity(unit, "structural", STRUCTURAL_LANE_INPUTS)


def measured_lane_identity(unit: dict) -> dict[str, str]:
    return _claimed_identity(unit, "measured", MEASURED_LANE_INPUTS)
