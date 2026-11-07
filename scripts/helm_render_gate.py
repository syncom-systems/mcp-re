#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Helm chart render gate — the fail-closed guards must actually refuse (CI gate).

`deploy/helm/mcp-re-proxy/templates/_helpers.tpl` carries the chart's security
guards: refuse a fleet on a node-local replay cache, refuse a plaintext Redis hop
carrying admitted nonces, refuse the shipped `did:example:` / `example.com` /
`epoch-1` placeholders, refuse a transport binding that cannot start, refuse an
admission ceiling of zero. Each is a `{{- fail ... }}` that runs at render time.

None of them had a test. A guard whose only proof is that someone read it is one
`{{- if }}` edit away from silently admitting, and the failure mode is quiet: the
chart renders, the pods start, and the property is gone. Worse, several of these
guards key on values Helm treats as FALSY (`0`, `""`), so an inverted condition
does not error — it omits a flag, and an omitted flag is the permissive default.

This gate renders the chart under a matrix of value sets and asserts, for each,
whether rendering must SUCCEED or must FAIL — and when it must fail, that the
refusal message names the value at fault. It also pins the rendered argv for the
cases where "renders successfully" is not the whole property: a flag that must be
present, and a flag that must be ABSENT; the pod-spec FIELDS that argv cannot
express (the apiserver token, the read-only root filesystem, the retention
volume); and three couplings the chart cannot check against itself, because a
chart can be flawless in isolation and still describe something the rest of the
system does not do — a `keySource` the image was never compiled for, a non-root
uid that lives only in the chart and not in the image, and a documented default
that is not the constant the proxy actually applies.

Requires the `helm` binary. Absence is a hard error, not a skip: a gate that
skips itself on the machine where it matters is the same defect it exists to
catch.

Run:  python3 scripts/helm_render_gate.py
      python3 scripts/helm_render_gate.py --selftest   # the text checks, no helm
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helm_render.runner import run_gate  # noqa: E402
from _helm_render.selftest import selftest  # noqa: E402


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return run_gate()


if __name__ == "__main__":
    sys.exit(main())
