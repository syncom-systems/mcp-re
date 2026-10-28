# THM-0101: the success tail's advancer — correction for owner review, 2026-10-27

Prepared for the owner's specification review of THM-0101 and, through its dependency, THM-0074.
**No review record, claim-correction record or approval has been written.** Every theorem whose
claim this change moves stays unreviewed at its new text until the owner records a review, and
the claim-surface gate refuses this branch until then.

## The change

One clause of THM-0101's statement. Nothing else in the theorem moves: security consequence,
scope, severity (`high`), `depends_on`, `supported_by`, owner and review requirement are
unchanged.

| | text |
|---|---|
| ratified | The success tail — `EvidenceRetained`, then `TerminalResponseServed` or `OpenLegResponseServed` — is advanced only by **`ExchangeProgress::publish`**, after `may_publish` has checked the same tail, and the serving path advances none of them itself. |
| corrected | The success tail — `EvidenceRetained`, then `TerminalResponseServed` or `OpenLegResponseServed` — is advanced only by **`PublishPermit::publish`**, after `may_publish` has checked the same tail, and the serving path advances none of them itself. |

## Why

#1253 (squash `e236f1d4`) deleted `ExchangeProgress::publish`. `may_publish` now returns a
`PublishPermit` (`mcp-re-proxy/src/exchange_state/publication.rs`), and `PublishPermit::publish`,
which consumes it, is the only code that advances the success tail. The ratified sentence names a
method that does not exist. Read at HEAD `40a31421`, the proposition it states is otherwise accurate:

- `may_publish` is the permit's only producer and `publish` its only consumer; the fields are
  private to `exchange_state::publication` (structural probes S76, S77).
- `publish` advances `ServedSuccess::tail()`, the same tail `may_publish` checked
  (`exchange_state.rs`, `ServedSuccess::tail`).
- No `advance` of a tail event exists under `http_profile_serve/`:
  `exchange_transition_ownership_test::no_terminal_the_owner_publishes_is_advanced_by_the_serving_path_again`.

The correction states nothing stronger than the ratified text did. In particular, it does not add
that a permit publishes only to the exchange that cleared it, which that exchange cannot change
first (S78, S79). That is a stronger fact the theorem could state, and it is left for the owner to
decide.

## What moved

A theorem fingerprint reads `verification/policy/theorems.toml` and nothing else, so these are the
whole effect of the change.

| theorem | what moved | fingerprint at main | fingerprint corrected |
|---|---|---|---|
| THM-0101 | its claim (`theorem_claim` `728308eb…` → `f5f6b4e5…`) | `sha256:4dc7e4a70e82dc5fd1ba9638b5d4ce1f2582494e736d3f700d9ba6e6f202a96c` | `sha256:9f9745bcb0bf2af74553369994a9ebb140e60965c42b8762f2d55e8be76a9641` |
| THM-0074 | its dependency digest for THM-0101 only; its own claim text is unchanged | `sha256:028d4960ba16858649fd3d1f96ce741d4cfa4cf3fdc0eb2af3617ce473c8188f` | `sha256:d5f490dbe84378272fb8afa20efcc9aa0f97b2033a94b126e84192de39d81614` |

## Why this is not a recorded Phase-1 correction

The ADR-MCPRE-068 Phase-1 ruling (2026-09-18) would cover the wording itself. The record cannot be
written for THM-0074. Its owner review is at `028d4960`, and the nine correction records on disk
for THM-0074 start from earlier fingerprints. `_claim_corrections.chain` requires every record for
a subject to lie on one chain from the reviewed fingerprint, so a tenth record starting at
`028d4960` leaves the nine as dead rows, and the gate refuses. Making it pass would mean deleting
those records or relaxing the totality rule. Both weaken the gate, so neither is done.

## What closes it

The owner's specification review of THM-0101 and THM-0074 at the corrected fingerprints. Both
require "Owner security-specification review". `tools/verification/review --fingerprint THM-0101`
and `--fingerprint THM-0074` print the components a record names.

THM-0101's review is also stale for a separate reason. #1253 and #1256 changed the supporting
semantics of `proxy.exchange_publication` and `proxy.exchange_transition_ownership`, so its review
digest has moved too. One reading at this branch's HEAD covers both.

## Addendum: the owner's ruling, and a third theorem the inventory missed

The owner ruled on 2026-10-27. The ruling is transcribed in
[`rulings/thm-0101-permit-publish-2026-10-27.md`](../rulings/thm-0101-permit-publish-2026-10-27.md):
the THM-0101 correction is accepted, and THM-0074's unchanged claim is reaffirmed at its updated
dependency fingerprint. The two specification records are written at the fingerprints above,
re-measured on the candidate.

The table under "What moved" is incomplete. THM-0136 also depends on THM-0101, so its fingerprint
moves too: `sha256:fe590f85…` → `sha256:37a7bedb…`. Its own statement, consequence, scope,
severity and `depends_on` are byte-identical. The ruling does not name it. It is carried by an
ADR-MCPRE-068 Phase-1 dependency-propagation record,
`verification/claim-corrections/THM-0136-thm-0101-permit-publish-2026-10-27.json`. That record is
the single link from its reviewed fingerprint. It is not an owner review: THM-0136's
specification axis reads stale until the owner reviews it at the new fingerprint.
