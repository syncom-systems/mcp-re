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


def _text(path: str) -> str | None:
    """The file's text, stripped; None when it is missing or empty."""
    return (_read(path) or "").strip() or None


def _identity(bundle_hint: str | None) -> dict:
    return {
        "lightsail_bundle": bundle_hint,
        "architecture": platform.machine(),
        "vcpus_online": os.cpu_count(),
        "vcpus_usable": len(getattr(os, "sched_getaffinity")(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count(),
    }


_CPU_FLAGS = {"avx2", "avx512f", "aes", "sha_ni", "vaes", "vpclmulqdq", "constant_tsc", "nonstop_tsc"}


def _cpu(lscpu: dict[str, str]) -> dict:
    return {
        "cpu_model": lscpu.get("Model name"),
        "cpu_vendor": lscpu.get("Vendor ID"),
        "threads_per_core": lscpu.get("Thread(s) per core"),
        "cores_per_socket": lscpu.get("Core(s) per socket"),
        "sockets": lscpu.get("Socket(s)"),
        "numa_nodes": lscpu.get("NUMA node(s)"),
        "hypervisor": lscpu.get("Hypervisor vendor"),
        "virtualization_type": lscpu.get("Virtualization type"),
        "cpu_flags_sample": " ".join(sorted(set((lscpu.get("Flags") or "").split()) & _CPU_FLAGS)),
    }


def _memory_and_disks() -> dict:
    root = shutil.disk_usage("/")
    return {
        "mem_total_kib": _meminfo_kib("MemTotal"),
        "root_disk_total_bytes": root.total,
        "root_disk_free_bytes": root.free,
        "block_devices": _cmd(["lsblk", "-dno", "NAME,SIZE,ROTA,TYPE,MODEL"]),
    }


def _kernel_and_os() -> dict:
    release = _os_release()
    return {
        "os_release": {k: release.get(k) for k in ("PRETTY_NAME", "ID", "VERSION_ID")},
        "kernel": platform.release(),
        "kernel_version": platform.version(),
        "clocksource": _text("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
        "cpufreq_governor": _text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "smt_active": _text("/sys/devices/system/cpu/smt/active"),
        "transparent_hugepage": _text("/sys/kernel/mm/transparent_hugepage/enabled"),
    }


def _toolchain() -> dict:
    return {
        "container_runtime": _cmd(["docker", "version", "--format", "{{.Server.Version}}"]),
        "redis_server_version": _cmd(["redis-server", "--version"]),
        "python": platform.python_version(),
        "bazel": _cmd(["bazel", "--version"]),
    }


def _limits() -> dict:
    return {
        "nofile_soft": _cmd(["sh", "-c", "ulimit -Sn"]),
        "nofile_hard": _cmd(["sh", "-c", "ulimit -Hn"]),
        "fs_file_max": _text("/proc/sys/fs/file-max"),
        "ip_local_port_range": _text("/proc/sys/net/ipv4/ip_local_port_range"),
        "tcp_tw_reuse": _text("/proc/sys/net/ipv4/tcp_tw_reuse"),
        "somaxconn": _text("/proc/sys/net/core/somaxconn"),
        "tcp_max_syn_backlog": _text("/proc/sys/net/ipv4/tcp_max_syn_backlog"),
    }


_TOOLS = ("mpstat", "pidstat", "vmstat", "sar", "ss", "perf", "redis-server", "redis-cli", "taskset")


def inventory(bundle_hint: str | None = None) -> dict:
    return {
        **_identity(bundle_hint),
        **_cpu(_lscpu()),
        **_memory_and_disks(),
        **_kernel_and_os(),
        **_toolchain(),
        "limits": _limits(),
        "tools": {t: shutil.which(t) is not None for t in _TOOLS},
        "loadavg": _text("/proc/loadavg"),
        "uptime": _text("/proc/uptime"),
    }


def _vcpu_problems(facts: dict, vcpus: int | None) -> list[str]:
    if vcpus is None:
        return []
    found = []
    if facts.get("vcpus_usable") != vcpus:
        found.append(f"usable vCPUs {facts.get('vcpus_usable')} != declared {vcpus}")
    if facts.get("vcpus_online") != vcpus:
        found.append(f"online vCPUs {facts.get('vcpus_online')} != declared {vcpus}")
    return found


def _arch_problems(facts: dict, arch: str | None) -> list[str]:
    if arch is None or facts.get("architecture") == arch:
        return []
    return [f"architecture {facts.get('architecture')} != declared {arch}"]


def _meets_memory(mem_kib: int | None, min_mem_gib: float) -> bool:
    """MemTotal sits below the bundle's nominal size; 7% is allowed for the kernel."""
    return mem_kib is not None and mem_kib >= min_mem_gib * 1024 * 1024 * 0.93


def _memory_problems(facts: dict, min_mem_gib: float | None) -> list[str]:
    mem = facts.get("mem_total_kib")
    if min_mem_gib is None or _meets_memory(mem, min_mem_gib):
        return []
    return [f"MemTotal {mem} KiB is below the declared {min_mem_gib} GiB (7% kernel allowance)"]


def check_expected(facts: dict, vcpus: int | None, arch: str | None, min_mem_gib: float | None) -> list[str]:
    """Reasons the host is NOT the declared measurement context; empty when it is."""
    return [*_vcpu_problems(facts, vcpus), *_arch_problems(facts, arch),
            *_memory_problems(facts, min_mem_gib)]
