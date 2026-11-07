# SPDX-License-Identifier: Apache-2.0
"""Rendering the chart with a values set, and reading the rendered argv back."""

from __future__ import annotations

import json
import subprocess
import tempfile
from itertools import dropwhile
from pathlib import Path

from _helm_render.config import CHART

# A values set that overrides every guard-tripping default, so the BASE render is
# expected to succeed. Each case below perturbs exactly one thing from here, which
# is what makes a failure attributable.
BASE = {
    "inner": {"httpUrls": ["http://inner-mcp.default.svc.cluster.local:8080/mcp"]},
    "identity": {
        "audience": "did:web:proxy.internal",
        "serverSigner": "did:web:proxy.internal",
        "serverKeyId": "server-key-1",
        "targetUri": "https://proxy.internal:8600/mcp",
        "trustDomain": "proxy.internal",
        "route": "",
        "delegatedTrustEpoch": "epoch-2026-07",
    },
}


def merged(*overlays: dict) -> dict:
    """BASE with `overlays` applied, one nesting level deep (all this chart needs)."""
    out = {key: (dict(value) if isinstance(value, dict) else value) for key, value in BASE.items()}
    for overlay in overlays:
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(out.get(key), dict):
                out[key].update(value)
            else:
                out[key] = value
    return out


def render(values: dict) -> tuple[bool, str]:
    """Render the chart with `values`. Returns (succeeded, combined output)."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        json.dump(values, handle)  # JSON is valid YAML; avoids a yaml dependency
        path = handle.name
    try:
        proc = subprocess.run(
            ["helm", "template", "gate", str(CHART), "-f", path],
            capture_output=True,
            text=True,
        )
        return proc.returncode == 0, proc.stdout + proc.stderr
    finally:
        Path(path).unlink(missing_ok=True)


def container_args(output: str) -> list[str]:
    """The rendered container argv, read back off the manifest text.

    Deliberately textual rather than a YAML parse: the assertion is about the
    exact strings the chart emitted, and a parse would let a quoting change
    through unnoticed.
    """
    stripped = (line.strip() for line in output.splitlines())
    after_header = dropwhile(lambda line: line != "args:", stripped)
    next(after_header, None)
    args: list[str] = []
    for line in after_header:
        if line == "args:":
            continue
        if line.startswith("- "):
            args.append(line[2:].strip().strip('"'))
        elif line and not line.startswith("#"):
            break
    return args
