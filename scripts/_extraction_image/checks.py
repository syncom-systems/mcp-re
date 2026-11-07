# SPDX-License-Identifier: Apache-2.0
"""Every way the definition can fail to hold the image to pinned, digest-checked prebuilts."""

from __future__ import annotations

from _extraction_image.config import (
    ARCHIVES,
    BINARIES,
    BUILD_TOOLS,
    CHARON_PIN_FETCH,
    EXECUTABLES,
    PINNED_ARGS,
    UPSTREAM,
)
from _extraction_image.dockerfile import bare, build_args, instructions


def lock_problems(lock: dict) -> list[str]:
    """The pair is Aeneas's own, and each URL is a release asset of its project."""
    found: list[str] = []
    charon, aeneas = lock.get("charon", {}), lock.get("aeneas", {})
    if not charon.get("commit") or aeneas.get("charon_pin") != charon.get("commit"):
        found.append(
            f"[aeneas].charon_pin is {aeneas.get('charon_pin')!r} and [charon].commit is "
            f"{charon.get('commit')!r}: the pinned Charon is not the one the pinned Aeneas "
            "declares"
        )
    for table in ("charon", "aeneas"):
        tag = lock.get(table, {}).get("release_tag", "")
        url = lock.get(table, {}).get("linux_arm64_url", "")
        prefix = f"https://github.com/AeneasVerif/{table}/releases/download/{tag}/"
        if not tag or not url.startswith(prefix):
            found.append(f"[{table}].linux_arm64_url {url!r} is not a release asset of {prefix}")
    return found


def arg_problems(args: dict[str, str], lock: dict) -> list[str]:
    """Each pinned build argument defaults to what the lock records."""
    found: list[str] = []
    for arg, (table, key) in PINNED_ARGS.items():
        pinned = bare(str(lock.get(table, {}).get(key, "")))
        if not pinned:
            found.append(f"[{table}].{key} is not recorded, so {arg} pins nothing")
        elif args.get(arg) != pinned:
            found.append(f"ARG {arg} defaults to {args.get(arg)!r}; the lock pins {pinned!r}")
    return found


def _checked(run: str, digest_arg: str) -> bool:
    """True when `run` checks something against `${digest_arg}` with `sha256sum -c`."""
    return "${" + digest_arg + "}" in run and "sha256sum -c" in run


def _archive_problems(url_arg: str, digest_arg: str, runs: list[str]) -> list[str]:
    fetches = [run for run in runs if "${" + url_arg + "}" in run]
    if not fetches:
        return [f"no instruction downloads ${{{url_arg}}}"]
    return [f"${{{url_arg}}} is downloaded without checking ${{{digest_arg}}}"
            for run in fetches if not _checked(run, digest_arg)]


def _binary_problems(path: str, digest_arg: str, runs: list[str]) -> list[str]:
    if any(_checked(run, digest_arg) and path in run for run in runs):
        return []
    return [f"{path} is not checked against ${{{digest_arg}}}"]


def download_problems(runs: list[str]) -> list[str]:
    """Every archive download, and every executed binary, is checked against its digest."""
    found: list[str] = []
    for url_arg, digest_arg in ARCHIVES.items():
        found += _archive_problems(url_arg, digest_arg, runs)
    for path, digest_arg in BINARIES.items():
        found += _binary_problems(path, digest_arg, runs)
    return found


def _run_problems(run: str) -> list[str]:
    found: list[str] = []
    tool = BUILD_TOOLS.search(run)
    if tool:
        found.append(f"an instruction invokes `{tool.group(1)}`: {run[:120]}")
    for reference in UPSTREAM.finditer(run):
        text = reference.group(0)
        if "/releases/download/" not in text and text != CHARON_PIN_FETCH:
            found.append(f"an instruction fetches {text} outside a pinned release")
    return found


def build_problems(steps: list[str], runs: list[str]) -> list[str]:
    """No instruction builds from source or reaches the upstream repositories off-release."""
    found = [problem for run in runs for problem in _run_problems(run)]
    for step in steps:
        if not step.startswith(("ARG ", "RUN ")):
            found.extend(f"{step.split()[0]} references {m.group(0)}"
                         for m in UPSTREAM.finditer(step))
    return found


def executable_problems(steps: list[str]) -> list[str]:
    """`CHARON_EXE` and `AENEAS_EXE` name the installed release binaries."""
    env = " ".join(step for step in steps if step.startswith("ENV "))
    return [f"{name} does not name the installed release binary {path}"
            for name, path in EXECUTABLES.items() if f"{name}={path}" not in env]


def problems(dockerfile: str, lock: dict) -> list[str]:
    steps = instructions(dockerfile)
    runs = [step for step in steps if step.startswith("RUN ")]
    return [
        *lock_problems(lock),
        *arg_problems(build_args(steps), lock),
        *download_problems(runs),
        *build_problems(steps, runs),
        *executable_problems(steps),
    ]
