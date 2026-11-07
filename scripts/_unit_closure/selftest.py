"""The gate's selftest: synthetic trees prove each rule, one in-tree probe proves the wiring."""

from __future__ import annotations

from _unit_closure import selftest_escapes, selftest_register
from _unit_closure.config import REPO, exclusions
from _unit_closure.register import check_register
from _unit_closure.rules import flag
from _unit_closure.selftest_support import Verdicts

_ESCAPED = (
    "mcp-re-proxy/src/signing_plane/rotation.rs",
    "mcp-re-proxy/src/signing_plane/mint_successor.rs",
    "mcp-re-proxy/src/signing_plane/trust_epoch_advance.rs",
)


def in_tree_probe() -> bool:
    """Replay the `signing_plane` split against the live manifest and register."""
    from _manifest import load_verification  # noqa: PLC0415 - real-run only

    escaped = list(_ESCAPED)
    units = [
        {"id": u["id"], "paths": [p for p in u["paths"] if p not in escaped]}
        for u in load_verification()["unit"]
    ]
    register = {k: v for k, v in exclusions().current().items() if k not in escaped}
    findings, walked = flag(REPO, units)
    problems = check_register(findings, register)
    missing = [rel for rel in escaped if not any(rel in p for p in problems)]
    if missing:
        print(
            f"SELFTEST FAILED [P13 in-tree probe]: removing {missing} from every unit and "
            f"from the register left the gate green. It is not wired to this repository."
        )
        return False
    if walked == 0:
        print("SELFTEST FAILED [P13 in-tree probe]: walked no files")
        return False
    return True


def selftest() -> int:
    verdicts = Verdicts()
    for prop in (*selftest_escapes.ALL, *selftest_register.ALL):
        prop(verdicts)

    # P13 — the in-tree probe. The synthetic cases prove the RULE; this one proves the gate
    # is wired to this repository's actual documents. The historical escape is replayed by
    # removing the three `signing_plane` submodules from whatever answers for them today.
    if not in_tree_probe():
        verdicts.ok = False

    if not verdicts.ok:
        return 1
    print(
        "unit-closure gate selftest: PASS (the split and rename escapes, the deciding "
        "parent and the namespace exemption, an entry's scope, the ratchet, the "
        "out-of-cone reason, the disposition lifecycle, UC-3, non-code `mod`, both module forms, "
        "the empty-scope refusal, and the signing_plane escape replayed in-tree)"
    )
    return 0
