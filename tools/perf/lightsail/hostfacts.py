# SPDX-License-Identifier: Apache-2.0
"""The host's identity, measured — never declared in advance.

`inventory()` records what the instance actually is. `check_expected()` refuses to measure
on anything other than the declared context: a Lightsail bundle that came up with a
different vCPU count or architecture is a different experiment, and stopping before the
sweep is cheaper than discovering it in the summary."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path


def _cmd(argv: list[str]) -> str | None:
    if shutil.which(argv[0]) is None:
        return None
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (out.stdout + out.stderr).strip() if out.returncode == 0 else None


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text()
    except OSError:
        return None


def _os_release() -> dict[str, str]:
    text = _read("/etc/os-release") or ""
    return {k: v.strip('"') for k, _, v in (line.partition("=") for line in text.splitlines()) if k}


def _meminfo_kib(key: str) -> int | None:
    match = re.search(rf"^{key}:\s+(\d+) kB", _read("/proc/meminfo") or "", re.M)
    return int(match.group(1)) if match else None


def _lscpu() -> dict[str, str]:
    text = _cmd(["lscpu"]) or ""
    return {k.strip(): v.strip() for k, _, v in (line.partition(":") for line in text.splitlines()) if v}


def inventory(bundle_hint: str | None = None) -> dict:
    lscpu = _lscpu()
    root = shutil.disk_usage("/")
    facts = {
        "lightsail_bundle": bundle_hint,
        "architecture": platform.machine(),
        "vcpus_online": os.cpu_count(),
        "vcpus_usable": len(getattr(os, "sched_getaffinity")(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count(),
        "cpu_model": lscpu.get("Model name"),
        "cpu_vendor": lscpu.get("Vendor ID"),
        "threads_per_core": lscpu.get("Thread(s) per core"),
        "cores_per_socket": lscpu.get("Core(s) per socket"),
        "sockets": lscpu.get("Socket(s)"),
        "numa_nodes": lscpu.get("NUMA node(s)"),
        "hypervisor": lscpu.get("Hypervisor vendor"),
        "virtualization_type": lscpu.get("Virtualization type"),
        "cpu_flags_sample": " ".join(sorted(set((lscpu.get("Flags") or "").split()) & {
            "avx2", "avx512f", "aes", "sha_ni", "vaes", "vpclmulqdq", "constant_tsc", "nonstop_tsc"})),
        "mem_total_kib": _meminfo_kib("MemTotal"),
        "root_disk_total_bytes": root.total,
        "root_disk_free_bytes": root.free,
        "block_devices": _cmd(["lsblk", "-dno", "NAME,SIZE,ROTA,TYPE,MODEL"]),
        "os_release": {k: _os_release().get(k) for k in ("PRETTY_NAME", "ID", "VERSION_ID")},
        "kernel": platform.release(),
        "kernel_version": platform.version(),
        "clocksource": (_read("/sys/devices/system/clocksource/clocksource0/current_clocksource") or "").strip() or None,
        "cpufreq_governor": (_read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") or "").strip() or None,
        "smt_active": (_read("/sys/devices/system/cpu/smt/active") or "").strip() or None,
        "transparent_hugepage": (_read("/sys/kernel/mm/transparent_hugepage/enabled") or "").strip() or None,
        "container_runtime": _cmd(["docker", "version", "--format", "{{.Server.Version}}"]),
        "redis_server_version": _cmd(["redis-server", "--version"]),
        "python": platform.python_version(),
        "bazel": _cmd(["bazel", "--version"]),
        "limits": {
            "nofile_soft": _cmd(["sh", "-c", "ulimit -Sn"]),
            "nofile_hard": _cmd(["sh", "-c", "ulimit -Hn"]),
            "fs_file_max": (_read("/proc/sys/fs/file-max") or "").strip() or None,
            "ip_local_port_range": (_read("/proc/sys/net/ipv4/ip_local_port_range") or "").strip() or None,
            "tcp_tw_reuse": (_read("/proc/sys/net/ipv4/tcp_tw_reuse") or "").strip() or None,
            "somaxconn": (_read("/proc/sys/net/core/somaxconn") or "").strip() or None,
            "tcp_max_syn_backlog": (_read("/proc/sys/net/ipv4/tcp_max_syn_backlog") or "").strip() or None,
        },
        "tools": {t: shutil.which(t) is not None for t in
                  ("mpstat", "pidstat", "vmstat", "sar", "ss", "perf", "redis-server", "redis-cli", "taskset")},
        "loadavg": (_read("/proc/loadavg") or "").strip() or None,
        "uptime": (_read("/proc/uptime") or "").strip() or None,
    }
    return facts


def check_expected(facts: dict, vcpus: int | None, arch: str | None, min_mem_gib: float | None) -> list[str]:
    """Reasons the host is NOT the declared measurement context; empty when it is."""
    problems = []
    if vcpus is not None and facts.get("vcpus_usable") != vcpus:
        problems.append(f"usable vCPUs {facts.get('vcpus_usable')} != declared {vcpus}")
    if vcpus is not None and facts.get("vcpus_online") != vcpus:
        problems.append(f"online vCPUs {facts.get('vcpus_online')} != declared {vcpus}")
    if arch is not None and facts.get("architecture") != arch:
        problems.append(f"architecture {facts.get('architecture')} != declared {arch}")
    mem = facts.get("mem_total_kib")
    if min_mem_gib is not None and (mem is None or mem < min_mem_gib * 1024 * 1024 * 0.93):
        problems.append(f"MemTotal {mem} KiB is below the declared {min_mem_gib} GiB (7% kernel allowance)")
    return problems
