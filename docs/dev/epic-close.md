# Closing an epic

An epic is closed on **assurance closure**, not on a green verification run. A green
`verify --aggregate --gate` says the machine evidence composes. It does not say the owner's
reviews still cover the claims that evidence supports. Epics #1106 and #1143 each closed on a
green complete run while REVIEW_CURRENT fell from 133 to 41 (#1171).

## Cadence

| when | what runs | what it decides |
|---|---|---|
| every pull request | the required fast pre-merge checks | whether the PR may merge |
| epic end | one complete `verification.yml` run on the final `main` | whether the epic may close |

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
`assurance-closure-<run>-<attempt>`: the attestations, `review.json`, `attest.log` and
`closure.json`.

The epic closes when that line says `PASS`.

## Re-evaluating an earlier run

Evidence is bound to unit fingerprints, not to a commit, so a complete run still closes a later
commit whose unit fingerprints have not moved — for example after review records land.

```sh
tools/verification/assurance-closure --run <run-id> --out <empty dir>
```

The working tree must be clean. The run must be a `verification` run whose `aggregate` job
succeeded; its event must be `workflow_dispatch` or `schedule`.
