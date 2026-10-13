#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The self-hosted runner's Docker contract — two defects that only a real run could show.

The extraction lane is gated on a V2/V3 unit existing, so until one was declared it had
never executed. Its first two executions each failed on a property of the runner rather
than of the code, and each was hidden behind the previous one:

1. **`docker login` cannot persist a credential here.**

       error saving credentials - err: exit status 1,
       out: `User interaction is not allowed. (-25308)`

   `-25308` is `errSecInteractionNotAllowed` — the macOS keychain refusing a background
   service. Note *saving*: the registry ACCEPTED the token, so this is neither a bad
   credential nor a package-permissions problem. Pointing `DOCKER_CONFIG` at an empty
   directory does not avoid it either: the CLI detects `osxkeychain` as the platform
   default whenever the helper is on `PATH`, so a fresh config detects the same store.
   Measured on the runner, and then again in CI with `DOCKER_CONFIG` demonstrably set.

2. **An isolated config loses the docker CONTEXT as well as the store**, which is what
   working around (1) then produced: `failed to connect to the docker API at
   unix:///var/run/docker.sock`, on a runner whose Docker is colima.

Both went away entirely when the registry did. The extraction image is now built where it
is consumed and identified by its own content digest, so there is no login, no isolated
config, and no endpoint to name — the ordinary default context is correct. What survives is
the one durable rule, which is the FIRST defect and not the second: a self-hosted runner
here cannot persist a registry credential at all, so no job on one may try.

This gate exists because nothing else can see that: the lane runs only on a self-hosted
macOS runner, only when a unit asks it for evidence, and the failure looks like an ordinary
Docker error rather than like a contract being broken.

Run:  python3 scripts/self_hosted_docker_gate.py
      python3 scripts/self_hosted_docker_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

from workflow_reader import workflows  # noqa: E402

#: The runner label that identifies the machine this contract is about. A GitHub-hosted
#: Linux runner has no keychain and a working default socket, so `docker login` there is
#: correct and must not be flagged; no workflow here does one any more, and the rule stays
#: scoped so that adding a GitHub-hosted job that legitimately logs in does not trip a
#: contract about this Mac.
SELF_HOSTED = "self-hosted"

#: `docker login` anywhere in a command. The first form of this rule anchored at the start
#: of a line and so matched only a block scalar's body — a mutation probe against the real
#: workflow then walked straight past `run: docker login …` on one line. A gate whose rule
#: is narrower than the thing it forbids is a gate that reports nothing.
_DOCKER_LOGIN = re.compile(r"\bdocker\s+login\b")
#: The action that runs the same login for a step.
_LOGIN_ACTION = "docker/login-action"


def findings(root: Path) -> list[str]:
    """Every self-hosted job that breaks the contract, with the reason."""
    out: list[str] = []
    for workflow in workflows(root):
        for name, job in workflow.jobs.items():
            if SELF_HOSTED not in job.runs_on:
                continue
            # Comments explain WHY the contract exists and must not trip it: the reader
            # gives commands without them, the same distinction `slo_invocation_gate` draws
            # between an invocation and a paragraph warning about one.
            logs_in = any(
                _DOCKER_LOGIN.search(command.code) for command in job.commands() if not command.prints
            ) or any((step.uses or "").startswith(_LOGIN_ACTION) for step in job.steps)
            if logs_in:
                out.append(
                    f"{Path(workflow.path).relative_to(root)}: job `{name}` runs on a "
                    f"self-hosted runner and calls `docker login`. It cannot persist a "
                    f"credential there — the macOS keychain refuses a background service "
                    f"(-25308) — and an isolated DOCKER_CONFIG does not avoid it, because the "
                    f"CLI detects `osxkeychain` whenever the helper is on PATH. The extraction "
                    f"image is built where it is consumed and needs no registry at all."
                )
    return out


def _workflow(*, login: bool, self_hosted: bool = True) -> str:
    runs_on = "[self-hosted, macOS, ARM64]" if self_hosted else "ubuntu-24.04-arm"
    steps = ["      - name: creds", "        run: |"]
    if login:
        steps.append("          docker login ghcr.io -u u --password-stdin")
    steps += ["      - name: use", "        run: |", "          docker run --rm x"]
    return (
        "jobs:\n  extraction:\n    runs-on: " + runs_on + "\n    steps:\n"
        + "\n".join(steps)
        + "\n"
    )


def selftest() -> int:
    """The form that shipped, as a mutation the gate must catch.

    A gate that only ever passes proves nothing, and this is the exact form that reached the
    runner rather than a hypothetical.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".github" / "workflows").mkdir(parents=True)
        target = root / ".github" / "workflows" / "probe.yml"

        target.write_text(_workflow(login=True), encoding="utf-8")
        got = findings(root)
        if len(got) != 1:
            print(f"SELFTEST FAILED: a self-hosted docker login was not caught: {got}")
            return 1

        target.write_text(_workflow(login=False), encoding="utf-8")
        if findings(root):
            print("SELFTEST FAILED: a job that never logs in was flagged")
            return 1

        # A GitHub-hosted runner has no keychain, so the same call there is correct. A gate
        # that told the truth about the wrong machine would be worse than none.
        target.write_text(_workflow(login=True, self_hosted=False), encoding="utf-8")
        if findings(root):
            print("SELFTEST FAILED: a GitHub-hosted runner's docker login was flagged")
            return 1

        # The INLINE form, which the first version of this rule walked past.
        target.write_text(
            "jobs:\n  extraction:\n    runs-on: [self-hosted, macOS, ARM64]\n    steps:\n"
            "      - name: sneak\n        run: docker login ghcr.io -u u --password-stdin\n",
            encoding="utf-8",
        )
        if len(findings(root)) != 1:
            print("SELFTEST FAILED: an inline `run: docker login` was not caught")
            return 1

        # The action form of the same login.
        target.write_text(
            "jobs:\n  extraction:\n    runs-on: [self-hosted, macOS, ARM64]\n    steps:\n"
            "      - uses: docker/login-action@v3\n",
            encoding="utf-8",
        )
        if len(findings(root)) != 1:
            print("SELFTEST FAILED: a docker/login-action step was not caught")
            return 1

        # A comment explaining the contract is not a breach of it.
        target.write_text(
            "jobs:\n  extraction:\n    runs-on: [self-hosted, macOS, ARM64]\n    steps:\n"
            "      - name: note\n        run: |\n"
            "          # NOT `docker login`: it cannot persist here.\n"
            "          docker run --rm x\n",
            encoding="utf-8",
        )
        if findings(root):
            print("SELFTEST FAILED: a comment naming docker login was read as a call")
            return 1

    print("self-hosted docker gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    found = findings(REPO)
    if found:
        print("self-hosted docker gate: FAIL", file=sys.stderr)
        for entry in found:
            print(f"  {entry}", file=sys.stderr)
        return 1
    print("self-hosted docker gate: OK — no self-hosted job tries to log in to a registry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
