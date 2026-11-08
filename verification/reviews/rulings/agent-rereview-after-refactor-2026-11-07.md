<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent re-reading of stale specification reviews after the Code Health refactor — 2026-11-07

**What this file is.** A transcription, by the agent preparing the records, of the owner's
in-session directive of 2026-11-07.

**What this file is not.** It is not an owner signature and does not ratify any claim. The
records it authorizes name the agent as reviewer and say so. No line in
`docs/security/owner-approvals-*.jsonl` signs them, and none is appended here.

## 1. The directive (verbatim)

> yes, start the re-reviews

It answered the agent's proposal: prepare agent-named re-review records, one group of theorems
at a time, starting with the units the refactor touched, each stating whether the claim still
holds against the new source, with draft ledger lines left for the owner to sign.

## 2. What the records may and may not say

- A record is written only for a theorem whose claim the agent re-read against the changed
  supporting source and found still to hold. A theorem whose claim no longer holds, or whose
  reading the agent cannot complete, gets no record and is reported.
- `reviewer` names the agent and states that the record is not an owner signature.
- The evidence class stays as registered. Nothing here upgrades a V0 unit to a proof.

## 3. Why the claims went stale

The Code Health campaign (behaviour-preserving refactors, #1313 onward) moved supporting source
between files and changed internal signatures. Each record's `notes` names what moved for that
theorem.
