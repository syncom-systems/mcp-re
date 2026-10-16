#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select the ONE live pod of a single-replica Deployment from `kubectl get pod -o json`.

Proof 4 runs its request loop inside the in-cluster load generator, so the pod it execs
into must be one that will still exist when the loop ends. "Newest Ready pod" is not that
predicate. On a fresh cluster `kubectl apply` and the following `rollout restart` create two
pods within the same second: `creationTimestamp` has one-second resolution and cannot order
them, and the replaced pod stays Ready for its whole termination grace period (its PID 1 is
`sleep infinity`, which ignores SIGTERM). Selecting it runs Proof 4 inside a pod that is
SIGKILLed mid-loop, and the proof reports a missing summary about a rollout it never saw.

So a pod being deleted is EXCLUDED, not merely outranked: eligible means Ready=True and no
`metadata.deletionTimestamp`. Exactly one eligible pod is the only answer. Zero or several
is reported as such, and the caller retries; a tie is never broken by name or position,
because neither says which pod the Deployment intends to keep.

Run:  kubectl get pod -l app=X -o json | python3 docs/security/fleet_pod_select.py
      python3 docs/security/fleet_pod_select.py --selftest
Exit: 0 and the pod name on stdout; 3 no eligible pod; 4 more than one eligible pod.
"""

from __future__ import annotations

import json
import sys

NONE_ELIGIBLE = 3
AMBIGUOUS = 4


def _ready(pod: dict) -> bool:
    conditions = pod.get("status", {}).get("conditions") or []
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)


def eligible(pods: list[dict]) -> list[str]:
    """Names of the pods that are Ready and not being deleted."""
    return [
        pod["metadata"]["name"]
        for pod in pods
        if _ready(pod) and not pod["metadata"].get("deletionTimestamp")
    ]


def select(document: dict) -> tuple[int, str]:
    names = eligible(document.get("items") or [])
    if not names:
        return NONE_ELIGIBLE, "no pod is Ready and not terminating"
    if len(names) > 1:
        return AMBIGUOUS, f"{len(names)} pods are Ready and not terminating: {', '.join(sorted(names))}"
    return 0, names[0]


def _pod(name: str, created: str, ready: bool, deleting: str | None = None) -> dict:
    meta = {"name": name, "creationTimestamp": created}
    if deleting:
        meta["deletionTimestamp"] = deleting
    return {
        "metadata": meta,
        "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}]},
    }


def selftest() -> int:
    same_second = "2026-10-15T14:53:07Z"
    # THE REGRESSION: old and new pod created in the same second, the old one still Ready
    # through its grace period. Listed in both orders, so neither sort position nor name
    # can be what selects the live pod.
    old = _pod("mcp-re-loadgen-7c9f-zzzzz", same_second, True, deleting="2026-10-15T14:53:09Z")
    new = _pod("mcp-re-loadgen-5b4d-aaaaa", same_second, True)
    for items in ([old, new], [new, old]):
        assert select({"items": items}) == (0, "mcp-re-loadgen-5b4d-aaaaa"), items

    # The pre-fix selector (newest Ready by creationTimestamp, last wins) picks the
    # terminating pod in one of the two orders — the defect this unit exists to remove.
    def pre_fix(items: list[dict]) -> str:
        ordered = sorted(items, key=lambda p: p["metadata"]["creationTimestamp"])
        return [p["metadata"]["name"] for p in ordered if _ready(p)][-1]

    assert pre_fix([new, old]) == "mcp-re-loadgen-7c9f-zzzzz"

    # Only a terminating pod is Ready: there is no live pod yet, which is not a selection.
    code, _ = select({"items": [old, _pod("n", same_second, False)]})
    assert code == NONE_ELIGIBLE
    # Two live pods: ambiguous, never resolved by spelling.
    code, why = select({"items": [new, _pod("mcp-re-loadgen-5b4d-bbbbb", same_second, True)]})
    assert code == AMBIGUOUS and "2 pods" in why
    assert select({"items": []})[0] == NONE_ELIGIBLE
    print("fleet_pod_select selftest: OK (same-second terminating pod excluded in both orders)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    code, out = select(json.load(sys.stdin))
    print(out, file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
