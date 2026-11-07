"""The in-process checks that are not a Bazel run: the module-size ratchet and the registry gates."""
from __future__ import annotations

import os

import size_debt


def _size_verdict(rc: int, soft: bool, debt: list) -> str:
    if rc == 0:
        return "ok"
    if not soft:
        return "new-failures"
    return "size-debt" if debt else "ok"


def size_part(rc: int, out: str, edited: list[str]) -> dict:
    soft, debt = size_debt.classify("module-size", out) if rc else (False, [])
    debt = size_debt.attributable(debt, edited) if soft else []
    verdict = _size_verdict(rc, soft, debt)
    record = size_debt.encountered(edited)
    untouched_growth_only = bool(rc and soft and not debt)
    # `exit` is this writer's status, so it agrees with the verdict the journal and the
    # reviewer read: growth in files the writer did not touch, and recorded size debt, are
    # not a failure of this change. The script's own status stays as `raw_exit`.
    return {"gate": "module-size", "verdict": verdict,
            "exit": 1 if verdict == "new-failures" else 0, "raw_exit": rc,
            **({} if rc == 0 else {"head": out.strip().splitlines()[-5:]}),
            **({"debt": debt} if debt else {}),
            **({"record": record} if record else {}),
            **({"note": "size growth only in files this writer did not touch"}
               if untouched_growth_only else {})}


def registry_part(script: str, rc: int, out: str) -> dict:
    return {"gate": "registry", "lane": os.path.basename(script),
            "verdict": "ok" if rc == 0 else "new-failures", "exit": rc,
            **({} if rc == 0 else {"head": [ln for ln in out.splitlines()
                                            if "FAIL" in ln or ln.startswith("  ")][:5]})}
