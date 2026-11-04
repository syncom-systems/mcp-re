# THM-0101 — the refusal route (2026-11-04)

Prepared for the owner's substantive review. This packet and its correction records are not
an approval, and they write no ledger line. THM-0101 and THM-0136 stay non-current on the
specification-review axis until the owner reviews them at the fingerprints below.

## The discrepancy

Found by the v0.20.0 census (`v0200-review-invalidation-2026-11-04.md`, packet #1277).

#1277 made a refusal enter its terminal: `HttpProfileProxy::disposition`
(`mcp-re-proxy/src/http_profile_serve/mod.rs`) calls `ExchangeProgress::refuse()`
(`mcp-re-proxy/src/exchange_state/publication.rs`), which advances `ExchangeEvent::Refused`.

The reviewed statement said every event reaches the machine "in one of exactly two ways":

- a stage's `Established<T>`;
- the assembly's direct `advance` of exactly three events.

It also named the publication tail, so there were already three routes, and `Refused` was on
none of them. The control scanned `.advance(` only, so `p.refuse()` was invisible to it and
it stayed green.

## The measurement

Every variant `ExchangeEvent` declares (22), against the route each reaches the machine by:

| route | events | how it is measured |
|---|---|---|
| stage (`Established::new` in the serving path) | 15 | source scan of `http_profile_serve/**` |
| assembly (direct `advance`) | `BackendDispatched`, `ContinuationRetired`, `ContinuationNotRequired` | source scan, both directions |
| publication (`ServedSuccess::tail`, driven by `PublishPermit::publish`) | `EvidenceRetained`, `TerminalResponseServed`, `OpenLegResponseServed` | read from the `tail` body itself |
| refusal (`ExchangeProgress::refuse`) | `Refused` | crate-wide source scan; one site, `disposition` |

`NotificationAcknowledged` is stage-owned: the inner plane's carrier holds it, and the tail
reads that carrier's event.

The first run of the partition control found a gap in the stage scan.
`transport_binding_stage` bound the event to a local (`let checked =
ExchangeEvent::TransportBindingChecked;`) and passed the local to `Established::new`. The
scan reads `ExchangeEvent::` inside the argument list, so it never saw that stage's event.
The existing disjointness control therefore did not cover `TransportBindingChecked`
either. The event is now named at both carrier sites. Behaviour is unchanged.

## The correction

**THM-0101 statement:**

- "exactly two ways" becomes "exactly one of four routes".
- The refusal route is added. `Refused` is entered only by `ExchangeProgress::refuse`, which
  the crate calls at one site, `disposition`. It states no stage's work and is not one of the
  assembly's three. Which terminal it reaches is the relation's answer.
- "The two sets are disjoint" becomes a partition of the declared events.
- The refusal entry is measured in both directions.
- The refusal terminal carries no correspondence claim. Only its single entry is claimed.

**THM-0101 scope:**

- The refusal entry is measured crate-wide, because `refuse` is `pub(crate)`.
- Newly listed as not stated: that every refusal the serving path serves derives its
  disposition through `disposition`. That is refusal-site totality, which is THM-0081's
  evidence.
- Newly named as a source-text limit: an aliased or macro-generated call.

**Unchanged:** the stage-establishment and publication text, the security consequence, the
severity (high), `depends_on`, the supporting units and the review requirement.

**Title:** "and the refusal terminal" is appended. The title is outside the claim
fingerprint.

**Is it a Phase-1 precision correction?** The old text misdescribes the code: it states a
two-way exhaustiveness that has been false since #1277. The new clause is what "exactly"
needs in order to be true. It also adds a measured property, the refusal entry's single
site, so the owner decides whether this is precision or expansion. Either way, the review
axis stays stale until the owner reads the text.

| theorem | from (reviewed) | to |
|---|---|---|
| THM-0101 | `9f9745bcb0bf2af7` | `7a320454b3beb793` |
| THM-0136 (dependency propagation only) | `b58fc9fc3c312214` | `6827fd27deada381` |
| THM-0074 (dependency propagation only, transitive) | `d5f490dbe8437827` | `4f1576d588147566` |

The own statements, consequences, scopes, severities and `depends_on` of THM-0136 and THM-0074 are byte-identical.
It composes THM-0101 only for "a success terminal is reached only through the owner's
publication", and the correction leaves that text unchanged.

## The controls

All are in `mcp-re-proxy/tests/integration/exchange_transition_ownership_test.rs`, target
`//mcp-re-proxy:integration_test`. Each is claimed on `proxy.exchange_transition_ownership`.

| control | what fails it |
|---|---|
| `every_exchange_event_reaches_the_machine_by_exactly_one_route` | an event on no route or two; a route naming an undeclared event; `tail` drifting from `RELOCATED_TO_THE_OWNER` |
| `the_refusal_terminal_is_entered_only_by_refuse_from_the_disposition` | a `refuse()`, `ExchangeProgress::refuse` or `ExchangeEvent::Refused` anywhere in the crate outside the machine except once in `disposition`; `disposition` no longer refusing; a second named advance in the machine |
| `the_refusal_rule_would_catch_an_unauthorized_entry` | negative control: a second `refuse()`, a path call, a direct `advance(Refused)` and a second entry in `disposition` are each detected; the receipt's `refuse(..)` is not an entry; the partition rule refuses its three defect shapes |

**Mutations measured locally on 2026-11-04, each reverted:**

| mutation | result |
|---|---|
| `progress.refuse();` after `ContinuationNotRequired` (`reply_assembly/mod.rs`) | refusal-entry control RED |
| `p.refuse();` deleted from `disposition` | refusal-entry control RED |
| `TransportBindingChecked` through a local (the code before this change) | partition control RED |

The first two are registered as M629 and M630 in `verification/policy/mutation-probes.toml`.
The mutation lane has not measured them. They are unmeasured until the November 8 run.

## Unit descriptions corrected

- `proxy.exchange_transition_ownership`: it said "exactly six" assembly events; there are
  three. It now names the four routes.
- `proxy.publish_permit_sole_producer`: it said the permit "exposes [the exchange] only by
  shared reference". Since #1277 the permit also gives it back through `withdraw(self) ->
  &mut ExchangeProgress`, which consumes the permit. The structural probe's `producer_paths`
  already said so.

## A changed verification mechanism: superseded correction records

This change moves two claims whose correction history the owner's later reviews had already
replaced:

- THM-0136 has one record from 2026-10-27, superseded by the review at `b58fc9fc`.
- THM-0074 has nine records from 2026-09-18 to 2026-10-07, superseded by the review at
  `d5f490db`.

`_claim_corrections.chain` required every record for a subject to be on the walk out of the
reviewed fingerprint. Once a re-reviewed claim moved again, its history therefore failed as
"dead rows". The gate also refuses deleting a record, because that would destroy the audit
trail. Together the two rules left the history unretirable, so any re-reviewed claim with
correction history could never move again.

**The rule now:**

- **Authority:** it is still only the walk. A claim the walk does not carry to the tree is
  refused, whatever lies off it.
- **Records off a walk that reaches the tree:** they are SUPERSEDED history. They are
  accepted, and the gate's reason counts them.
- **Records off a walk that stops short:** they are still dead rows, and they are refused
  with the walk.
- **A walk with no live record:** refused.

`tools/verification/test_claim_corrections.py` pins all three cases. The owner should
confirm the rule. It relaxes hygiene, not soundness: no record off the walk can carry a
claim anywhere.
