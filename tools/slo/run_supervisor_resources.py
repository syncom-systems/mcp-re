"""What exists on the measurement plane, and who owns it."""

from __future__ import annotations

import os
import subprocess

import environment_preflight

OWNER_LABEL = "com.mcp-re.slo"
RUN_LABEL = "com.mcp-re.slo.run"

GRACE_S = float(os.environ.get("MCP_RE_SLO_TEARDOWN_GRACE_S", 10))
VERIFY_S = float(os.environ.get("MCP_RE_SLO_TEARDOWN_VERIFY_S", 30))


def endpoint() -> str:
    return environment_preflight.endpoint(environment_preflight.declared_class())


def docker(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return environment_preflight.docker(endpoint(), *args, timeout=timeout)


def _ids(*command: str) -> list[str]:
    return [i for i in (docker(*command).stdout or "").split() if i]


def owned_resources(run: str | None = None) -> dict:
    """Docker resources carrying our label, optionally narrowed to one run.

    `run=None` means every SLO-owned resource regardless of which run made it -- that is
    what reconciliation asks. A specific run is what teardown verification asks.
    """
    selector = [f"label={OWNER_LABEL}=true"]
    if run:
        selector.append(f"label={RUN_LABEL}={run}")
    filters: list[str] = []
    for s in selector:
        filters += ["--filter", s]

    containers = _ids("ps", "-aq", *filters)
    networks = _ids("network", "ls", "-q", *filters)
    volumes = _ids("volume", "ls", "-q", *filters)
    return {"containers": containers, "networks": networks, "volumes": volumes,
            "total": len(containers) + len(networks) + len(volumes)}


def unowned_outside_baseline() -> dict:
    """Things on the plane that are NOT ours, and therefore not ours to remove."""
    entry = environment_preflight.declared_class()
    plane = environment_preflight.inspect_plane(entry)
    ours = set(owned_resources()["containers"])
    strangers = [c for c in plane["containers"] if c["id"] not in ours
                 and f"{OWNER_LABEL}=true" not in (c.get("labels") or "")]
    return {"containers": strangers, "unapproved_images": plane["unapproved_images"]}
