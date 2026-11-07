# SPDX-License-Identifier: Apache-2.0
"""The measurement context: the class a measurement is about, never the machine."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import tomllib
from datetime import datetime, timedelta

from _slo_evidence import config
from _slo_evidence.config import BASELINE
from _slo_evidence.surface import sha256


def _docker_class() -> str:
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        return "absent"
    return "docker-" + ".".join(probe.stdout.strip().split(".")[:2])


def class_environment_digest(hardware_class: str) -> str:
    """A canonical digest of the class's declared environment.

    WHY THE CLASS NAME ALONE IS NOT ENOUGH.

    `hardware_class` distinguishes dev1-slo-v1 from its predecessor, which is what stops
    the old colima-db PASS being reused. It does NOT notice the declaration being edited
    underneath a stable name:

        environment A  -> PASS recorded under dev1-slo-v1
        edit [context.class.environment] in place
        environment B  -> preflight verifies B, name still dev1-slo-v1,
                          context digest unchanged -> A's PASS reused for B

    Folding this derived value into the context closes that path mechanically, so
    correctness does not depend on somebody remembering to bump v1 to v2. The human
    version in the name stays useful for reading; it is no longer load-bearing.

    The INDIVIDUAL fields are deliberately not copied into `measurement_context()`. The
    class declaration remains the one authority and this is a witness derived from it --
    restating the fields would create a second place they could drift.

    Canonical means sorted keys and fixed separators, so declaration key ORDER cannot move
    the digest: reordering a TOML table is not an environment change.
    """
    declared = tomllib.loads(config.SURFACE_TOML.read_text(encoding="utf-8"))["context"]["class"]
    entry = next((e for e in declared if e["name"] == hardware_class), None)
    environment = (entry or {}).get("environment") or {}
    canonical = json.dumps(environment, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode())


def measurement_context() -> dict[str, object]:
    """The class the measurement is about — never the machine, and never a timestamp.

    A timestamp belongs to the RECORD, not to the identity: two runs an hour apart on the
    same box answer the same question, and freshness is adjudicated separately.
    """
    anchor = json.loads(BASELINE.read_text(encoding="utf-8"))["anchor"]["config"]
    hardware_class = os.environ.get("MCP_RE_LOADGEN_HW_CLASS", anchor["hardware_class"])
    return {
        "hardware_class": hardware_class,
        # A witness derived from the class's own declaration, NOT a copy of its fields.
        # Without it, editing [context.class.environment] under a stable class name leaves
        # the identity unmoved and lets a PASS measured in the old environment be reused
        # in the new one.
        "hardware_class_environment_digest": class_environment_digest(hardware_class),
        "os_class": f"{platform.system()}-{platform.release().split('.')[0]}-{platform.machine()}",
        "container_runtime_class": _docker_class(),
        "cpu_count": os.cpu_count(),
        "concurrency": anchor["concurrency"],
        "requests": anchor["requests"],
        "connection_mode": anchor["connection_mode"],
        "declared_cores": 1,
    }


def context_digest(context: dict[str, object]) -> str:
    declared = tomllib.loads(config.SURFACE_TOML.read_text(encoding="utf-8"))["context"]["fields"]
    missing = [field for field in declared if field not in context]
    if missing:
        raise SystemExit(f"error: the context declares {missing} but the measurement supplies none")
    return sha256(json.dumps({k: context[k] for k in sorted(declared)}, sort_keys=True).encode())


def stale(recorded: datetime, window_days: int, now: datetime) -> bool:
    """Age is adjudicated on its own, because the context is a CLASS and not a machine.

    "arm64, 14 cores, macOS 25" is the same class before and after a firmware update, a
    thermal-paste year, or a background daemon nobody declared. The window is what keeps an
    identity from meaning "forever".
    """
    return (now - recorded) > timedelta(days=window_days)
