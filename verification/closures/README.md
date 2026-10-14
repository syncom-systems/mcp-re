# Assurance-closure records

One file per closed target, `<target commit>.json`, written by
`tools/verification/assurance-closure --record` from a passing closure (#1173). Each states that
its target tree closed assurance at the unit and theorem identities it lists.

These are derived historical evidence, not owner approvals, which is why they are not under
`verification/reviews/`. They are not attestations: nothing in the freshness graph reads this
directory, and a record establishes nothing about any tree but its target.

`tools/verification/closure-record --verify` checks every record here on each pull request. See
`docs/dev/epic-close.md`.
