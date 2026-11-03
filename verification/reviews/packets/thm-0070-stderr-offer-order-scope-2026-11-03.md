# THM-0070: the stream's order property is the collector's — scope precision, 2026-11-03

A Phase-1 precision correction under the ADR-MCPRE-068 campaign ruling of 2026-09-18. Recorded in
`verification/claim-corrections/THM-0070-stderr-offer-order-scope-2026-11-03.json`, and propagated
to THM-0071, which depends on THM-0070, in
`verification/claim-corrections/THM-0071-thm-0070-scope-propagation-2026-11-03.json`.
**A correction record is not an approval.** Both theorems' specification reviews stay STALE for
release-mode establishment until the owner reviews the new text.

## The change

One paragraph appended to THM-0070's `scope`. Statement, security consequence, severity
(`medium`), `depends_on`, `supported_by`, owner and review requirement are unchanged.

| | text |
|---|---|
| added to scope | The emission-order property is the collector's. The stderr sink writes lines in the order they are offered, and a record's `seq` is allocated when its event is produced, before the offer, so lines from concurrent producers can reach the stream out of `seq` order. Position is still carried by every line: a consumer orders a run by `seq`, and a gap is a gap whatever the arrival order. |

## Why (#1211, ADR-MCPRE-070 §16 item 5, fact F5)

The statement says "the collector preserves emission order". Its only order control is on
`CollectingAuditSink` (`audit_sink/mod.rs`). The stderr sink, the default production observer,
receives events already numbered at semantic production (#1202, ADR-MCPRE-070 §8) and offers each
line to its queue in call order (`StderrAuditSink::record` → `record_on` → `offer`). Two producers
can therefore offer `n + 1` before `n`. The scope did not say which sinks the order property
covers, so the claim could be read as stating stderr seq order, which production does not provide.

Executable witness: `audit_sink::stderr::tests::the_stream_is_in_offer_order_and_keeps_each_events_own_seq`
offers seq 1 and then seq 0 to the sink's queue, and the stream holds them in that order, each
under its own seq.

## Why this is a precision correction, not a weakening

- The statement already scopes order to "the collector". The added text names what was never
  established for stderr; it removes no property that any control measured.
- The security consequence ("a gap is visible in the sequence") is unchanged and still true on
  stderr: every line carries `(run, seq)`, so a hole is readable whatever the arrival order.
- Product behaviour is unchanged. The code change only adds a test seam (`record_on`) that
  `record` calls with the same queue, counters and ceiling.

## THM-0071

THM-0071's own statement, security consequence, scope, severity (`medium`), `depends_on` and
review requirement are byte-identical. Its fingerprint moved only through THM-0070's claim digest
in its dependency closure.
