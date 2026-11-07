"""Reconcile previous runs' leftovers, then assert the clean start."""

from __future__ import annotations

import time

import environment_preflight
from run_supervisor_resources import (
    GRACE_S,
    OWNER_LABEL,
    RUN_LABEL,
    VERIFY_S,
    docker,
    owned_resources,
    unowned_outside_baseline,
)


def _stale_containers(before: dict, current_run: str) -> list[str]:
    """The labelled containers that do not belong to `current_run`."""
    return [c for c in before["containers"]
            if current_run not in (docker("inspect", "-f",
                                          "{{index .Config.Labels \"" + RUN_LABEL + "\"}}",
                                          c).stdout or "")]


def _remove_containers(stale_containers: list[str]) -> list[str]:
    removed = []
    for cid in stale_containers:
        docker("stop", "-t", str(int(GRACE_S)), cid)
        docker("rm", "-fv", cid)
        removed.append(cid)
    return removed


def _remove_networks(networks: list[str]) -> list[str]:
    return [net for net in networks
            if docker("rm", "-f", "--", net).returncode == 0
            or docker("network", "rm", net).returncode == 0]


def _remove_volumes(volumes: list[str]) -> list[str]:
    return [vol for vol in volumes if docker("volume", "rm", "-f", vol).returncode == 0]


def _remove_stale(before: dict, stale_containers: list[str]) -> dict:
    # Networks and volumes carry the label too, so they are addressed the same way. A
    # network still holding a container refuses removal, which is why containers go first.
    containers = _remove_containers(stale_containers)
    networks = _remove_networks(before["networks"])
    volumes = _remove_volumes(before["volumes"])
    return {"containers": containers, "networks": networks, "volumes": volumes}


def _await_only_this_run_remains(current_run: str) -> None:
    deadline = time.monotonic() + VERIFY_S
    while owned_resources()["total"] > len(owned_resources(current_run)["containers"]):
        if time.monotonic() >= deadline:
            break
        time.sleep(1)


def reconcile_previous(current_run: str) -> dict:
    """Remove resources owned by PREVIOUS runs. Never anything unowned.

    Graceful first, then forced, then VERIFIED. A removal command that returns success is
    not evidence the resource is gone -- only re-reading the daemon is.
    """
    before = owned_resources()
    stale_containers = _stale_containers(before, current_run)
    removed = _remove_stale(before, stale_containers)
    _await_only_this_run_remains(current_run)

    after = owned_resources()
    survivors = [c for c in after["containers"] if c in stale_containers]
    return {"found": before, "removed": removed, "survivors": survivors,
            "reconciled": not survivors}


def _start_problems(env: dict, leftovers: dict, strangers: dict) -> list[str]:
    problems: list[str] = []
    if not env["verified"]:
        problems.append(f"the plane is not the declared environment: {env['mismatches']}")
    if leftovers["total"]:
        problems.append(f"SLO-owned resources from a previous run remain: {leftovers}")
    if strangers["containers"]:
        # NOT ours. This is an infrastructure condition, not something to clear.
        problems.append(
            f"INFRASTRUCTURE_UNAVAILABLE: {len(strangers['containers'])} unowned "
            f"container(s) occupy the measurement plane. They were not created by an SLO "
            f"run and will not be removed; resolve manually.")
    if strangers["unapproved_images"]:
        problems.append(f"unapproved images on the plane: {strangers['unapproved_images']}")
    return problems


def assert_clean_start(current_run: str) -> dict:
    """The exact declared baseline, or a refusal that says which kind of problem it is."""
    entry = environment_preflight.declared_class()
    env = environment_preflight.verify_environment(entry)
    plane = environment_preflight.inspect_plane(entry)
    strangers = unowned_outside_baseline()
    leftovers = owned_resources()

    problems = _start_problems(env, leftovers, strangers)
    return {"at_baseline": not problems, "problems": problems,
            "environment_verified": env["verified"], "plane": plane}
