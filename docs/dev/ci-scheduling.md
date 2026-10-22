# CI scheduling: what starts what

Pull requests and merges run bounded checks. Exhaustive verification runs only when someone
asks for it or the schedule fires. A change that invalidates every piece of formal evidence
does not, by that fact, start a remeasurement.

| workflow | starts on | does | bound |
|---|---|---|---|
| `pre-merge.yml` | every pull request, no path filter | structural gates, `bazel test`, lint, format, SDK suites | the required checks |
| `post-merge.yml` | every push to `main` | the same jobs, on the merged result | the same |
| `mcp-re-supply-chain.yml` | pull requests touching the dependency graph, `main`, daily | RustSec, yank and policy gate | the gate |
| `mutation-probe.yml` | pull requests touching probed code; weekly; dispatch | the mutation probes of the units the change moves | 30 minute timeout, at most 20 units; a platform change, a larger scope or a scope that cannot be computed applies no probe and is deferred |
| `verification.yml` | weekly schedule and dispatch only | the complete run: every unit, host and extraction lanes, aggregate, assurance closure | none: it is the full run |
| `assurance-closure.yml`, `release.yml`, `extraction-image.yml` | dispatch | as named | owner-started |
| `weekly.yml`, `test-inventory.yml`, `live-infra-e2e.yml`, `cloud-kms-live.yml` | schedule, dispatch; pull requests touching only the workflow file | as named | as named |

## Invalidation is not remeasurement

A change to `MODULE.bazel`, a lockfile, the Rust toolchain, the Verus pin or the verification
platform moves unit fingerprints. Nothing re-runs. The evidence that the old fingerprints
measured is reported as stale by `tools/verification/verify --gate` and `review`, and a unit
with no current record is INCOMPLETE or MISSING, never verified. The only way back to current
evidence is a complete run, which an owner dispatches, or the weekly schedule.

`tools/verification/assurance-closure` refuses any evidence that is not from a complete run at
the exact revision, so a closure verdict cannot be taken from the bounded probe.

## What enforces it

`scripts/verification_trigger_gate.py`, in the unconditional pre-merge job, proves:

1. `verification.yml` declares exactly `schedule` and `workflow_dispatch`, with no path filter,
   no `select-units` call, and a first job that fails on any other event.
2. No workflow calls it, follows it with `workflow_run`, or dispatches it.
3. `pre-merge.yml` has an unfiltered `pull_request` trigger and is callable; `post-merge.yml`
   starts on push to `main` and calls it.
4. `mutation-probe.yml` has no push trigger, a pull-request path filter, the timeout and unit
   cap above, defers when `select-units` fails, and installs no toolchain.
5. A pull request or push that changes `MODULE.bazel`, a lockfile, the toolchain pin, the
   verification platform or `verification.yml` itself starts no complete run, and
   `select-units` defers every verification-platform path the probe does start on.

Its selftest mutates the real workflows to reintroduce each defect and requires the gate to
name it.

## Starting a complete run

The owner dispatches `verification.yml` (and, for a release, `release.yml`). A Claude session
does not: the repository's PreToolUse hook refuses `gh workflow run` and the dispatch API. It
does not refuse opening a pull request, which starts only the bounded checks above.
