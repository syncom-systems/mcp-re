# Closing an epic

An epic is closed on **assurance closure**, not on a green verification run. A green
`verify --aggregate --gate` says the machine evidence composes. It does not say the owner's
reviews still cover the claims that evidence supports. Epics #1106 and #1143 each closed on a
green complete run while REVIEW_CURRENT fell from 133 to 41 (#1171).

## Cadence

| when | what runs | what it decides |
|---|---|---|
| every pull request | the required fast pre-merge checks, and the bounded mutation probe where a probed unit moved | whether the PR may merge |
| every merge to `main` | `post-merge.yml`: the pre-merge jobs on the merged result | whether `main` is sound |
| epic end | one complete `verification.yml` run on the final `main`, dispatched | whether the epic may close |

Nothing about assurance closure is added to the pull-request path.

## The closure criterion

Dispatch `verification.yml` on the final `main` commit. A dispatched or scheduled run is a
**complete** run (`scope.outputs.complete == 'true'`); after its `aggregate` job succeeds, the
`assurance-closure` job runs `tools/verification/assurance-closure`, which:

1. refuses evidence that is scoped, from a pull-request or push run, or not an aggregate `PASS`;
2. runs `tools/verification/attest` over the run's composed evidence into a fresh store, which
   refuses any unit whose fingerprint moved since it was measured;
3. runs `tools/verification/review --json` over that store;
4. fails unless every active theorem is REVIEW_CURRENT, EVIDENCE_ESTABLISHED and
   CURRENTLY_VERIFIED, and every declared system root is complete.

It prints each blocker — a stale review and the component that moved, a stale or unreviewed
assumption, a non-FRESH unit, a dependency-only blockage, an incomplete root and its blocker —
and exactly one `ASSURANCE CLOSURE: PASS|FAIL` line. The job uploads
`assurance-closure-<run>-<attempt>`: the attestations, `review.json`, `attest.log`,
`closure.json` and, on a PASS, `closure-record.json`.

The epic closes when that line says `PASS` and its closure record is committed.

## The committed closure record

The CI artifact expires; the record does not. Commit the PASS's `closure-record.json` as
`verification/closures/<target commit>.json`, or run the `--run` form below with `--record`,
which writes it there. It is tens of kilobytes. It states that the target tree closed at the
identities it lists:

- the target commit and tree, and the run (id, attempt, event, evidence commit);
- the verification policy revision and the review-ledger identity;
- every unit with its full fingerprint, and a canonical digest of that set;
- every active theorem with its fingerprint and semantic review digest, and a canonical
  digest of that set;
- the declared roots, the three axis counts and the root counts.

`tools/verification/closure-record --verify` runs on every pull request. It checks that each
record is well formed, that its digests are the digests of the identities it lists, and that its
target commit resolves to its target tree. A record stays valid as `main` advances, because
it is a statement about its target.

`tools/verification/closure-record --compare <record>` names each identity of the current tree
that differs from the record. IDENTICAL is a report. A record is not an attestation and makes no
later tree fresh; only attestations issued for that tree do.

## Re-evaluating an earlier run

Evidence is bound to unit fingerprints, not to a commit, so a complete run still closes a later
commit whose unit fingerprints have not moved — for example after review records land.

```sh
tools/verification/assurance-closure --run <run-id> --out <empty dir>
```

Or dispatch `assurance-closure.yml` with `run_id`, which runs the same command on the
dispatched commit and uploads the same records.

The working tree must be clean. The run must be a `verification` run whose `aggregate` job
succeeded; its event must be `workflow_dispatch` or `schedule`.
