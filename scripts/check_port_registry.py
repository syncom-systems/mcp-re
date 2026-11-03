#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Port-registry staleness gate.

`config/ports.toml` is the single source of truth for every port this repo
binds (see its header). Other artifacts that must carry a port — the Helm
chart's `bindPort` — hold a MIRRORED copy for tooling that cannot read the
registry at template time. A mirror that is only "asked to stay equal" by a
comment drifts; this gate makes the equality mechanical (ADR-MCPS-048:
generated/mirrored values are CI-staleness-gated, not trusted).

It also enforces the band invariant: every registered port must fall inside the
reserved band, so nothing in this repo can bind outside the machine-wide
reservation.

Exit 0 = registry, mirror, and band all consistent. Non-zero = drift. `--selftest`
checks the band and mirror rules against fixture texts.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PORTS_TOML = REPO / "config" / "ports.toml"
HELM_VALUES = REPO / "deploy" / "helm" / "mcp-re-proxy" / "values.yaml"
COMPOSE_DIR = REPO / "deploy" / "compose"


#: The proxy port as the compose reference spells it: the bind address, the published
#: mapping, and verify.sh's probe. Each must equal the registry.
COMPOSE_SPELLINGS = (
    ("compose.yaml", r"0\.0\.0\.0:(\d+)"),
    ("compose.yaml", r'\}:(\d+):(\d+)"'),
    ("verify.sh", r"^PORT=(\d+)$"),
)


def check_compose(proxy_port: int, texts: dict[str, str]) -> list[str]:
    """Every spelling of the proxy port in the compose reference equals the registry."""
    problems = []
    for name, pattern in COMPOSE_SPELLINGS:
        found = [int(n) for m in re.finditer(pattern, texts.get(name, ""), re.M) for n in m.groups()]
        if not found:
            problems.append(f"deploy/compose/{name}: no port matching /{pattern}/ (was it renamed?)")
        for port in found:
            if port != proxy_port:
                problems.append(
                    f"deploy/compose/{name}: port {port} != registry mcp_re_proxy.port ({proxy_port})"
                )
    return problems


def check(ports_text: str, values_text: str, compose: dict[str, str] | None = None) -> tuple[list[str], str]:
    """`(problems, summary)` for a registry text, a Helm values text and the compose files."""
    reg = tomllib.loads(ports_text)
    problems: list[str] = []

    # --- Band invariant: every service port is inside the reserved band -------
    band = reg["metadata"]["band"]
    lo, hi = (int(x) for x in band.split("-"))
    for name, svc in reg.get("services", {}).items():
        port = svc.get("port")
        if port is None:
            continue
        if not (lo <= port <= hi):
            problems.append(f"service '{name}' port {port} is outside the reserved band {band}")

    proxy_port = reg["services"]["mcp_re_proxy"]["port"]

    # --- Mirror check: Helm bindPort must equal the registry proxy port -------
    # values.yaml is plain YAML; read the `bindPort:` scalar without a YAML dep.
    m = re.search(r"^\s*bindPort:\s*(\d+)\s*(?:#.*)?$", values_text, re.M)
    if not m:
        problems.append(f"could not find a `bindPort:` scalar in {HELM_VALUES.relative_to(REPO)}")
    elif int(m.group(1)) != proxy_port:
        problems.append(
            f"Helm bindPort ({int(m.group(1))}) != registry mcp_re_proxy.port "
            f"({proxy_port}). Update deploy/helm/mcp-re-proxy/values.yaml to match "
            f"config/ports.toml (the source of truth)."
        )
    if compose is not None:
        problems.extend(check_compose(proxy_port, compose))
    return problems, f"band {band}, mcp_re_proxy={proxy_port}, Helm bindPort and compose mirror it."


def selftest() -> int:
    """A port outside the band, a drifted mirror and a missing mirror each go red."""
    ports = (
        '[metadata]\nband = "8600-8699"\n'
        '[services.mcp_re_proxy]\nport = 8601\n'
        '[services.other]\nport = 8650\n'
    )
    values = "proxy:\n  bindPort: 8601  # mirrors config/ports.toml\n"
    compose = {
        "compose.yaml": '- "0.0.0.0:8601"\n  - "${P:-127.0.0.1}:8601:8601"\n',
        "verify.sh": "PORT=8601\n",
    }
    drifted = {**compose, "verify.sh": "PORT=8602\n"}
    cases = [
        ("the registry and its mirror agreeing", ports, values, False),
        ("a service port outside the band", ports.replace("8650", "9650"), values, True),
        ("a Helm bindPort that drifted", ports, values.replace("8601", "8602"), True),
        ("a values file with no bindPort", ports, "proxy:\n  replicas: 2\n", True),
    ]
    failures = 0
    for label, ports_text, values_text, red in cases:
        problems, _ = check(ports_text, values_text)
        ok = bool(problems) == red
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}: {problems or 'clean'}")
        failures += not ok
    for label, texts, red in (
        ("compose spellings agreeing", compose, False),
        ("a compose probe port that drifted", drifted, True),
        ("compose files with no port at all", {}, True),
    ):
        problems = check_compose(8601, texts)
        ok = bool(problems) == red
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}: {problems or 'clean'}")
        failures += not ok
    if failures:
        print(f"port-registry gate selftest: FAIL ({failures})")
        return 1
    print("port-registry gate selftest: PASS")
    return 0


def main() -> int:
    compose = {n: (COMPOSE_DIR / n).read_text() for n in ("compose.yaml", "verify.sh")}
    problems, summary = check(PORTS_TOML.read_text(), HELM_VALUES.read_text(), compose)
    for problem in problems:
        print(f"port-registry gate: FAIL — {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"port-registry gate: OK — {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
