"""Controls for what the gate observes: quiescence, runner participation, process state."""

from __future__ import annotations

import itertools
import os
import subprocess
import sys
from pathlib import Path

import host_gate
import host_gate_config
from _host_gate_support import check

HERE = Path(__file__).resolve().parent


def _quiescence(loadavg, wait_s: float) -> dict:
    return host_gate.await_quiescence(wait_s=wait_s, loadavg=loadavg, sleep=lambda s: None)


def test_quiescence() -> None:
    print("\nquiescence adjudication (§8)")
    ncpu = os.cpu_count() or 1

    # The exact reading that was wrongly declared quiet: load1 had decayed, load5/load15
    # had not. The correction exists so that this reading is NOT admitted.
    failed = tuple(v * ncpu / 14 for v in (3.48, 5.73, 5.61))
    check("the failed run's load is REFUSED as quiescent",
          not _quiescence(lambda: failed, 1)["established"], f"l1/l5/l15={failed}")

    # POISON PILL for the load5/load15 clauses. Re-evaluate that same reading against a
    # load1-only predicate: it PASSES. So those two clauses are what carry the refusal --
    # they are load-bearing, not decorative, and dropping them reinstates the defect.
    load1_only_verdict = failed[0] <= ncpu * host_gate_config.Q_LOAD1 * 1.30
    check("PILL: a load1-only predicate admits the failed reading",
          load1_only_verdict,
          f"load1 fraction {failed[0] / ncpu:.2f} vs idle floor 0.10 — barely separable")

    quiet = (ncpu * 0.05,) * 3
    result = _quiescence(lambda: quiet, 60)
    check("a genuinely quiet host is admitted", result["established"])
    check("admission required consecutive samples",
          len(result["samples"]) >= host_gate_config.Q_SAMPLES)

    # A single quiet sample among noisy ones must not admit: the counter has to reset.
    # The noisy tail is infinite because `sleep` is stubbed out here -- the loop spins far
    # faster than the wall clock it is bounded by, so a finite fixture runs dry first and
    # the test fails on its own scaffolding rather than on the property.
    noisy = itertools.chain([(ncpu * 0.05,) * 3], itertools.repeat((ncpu * 0.9,) * 3))
    check("one quiet sample among noise does not admit",
          not _quiescence(lambda: next(noisy), 1)["established"])

    # The measured idle floor of dev1 must actually satisfy the policy, or the lane can
    # never run. A threshold below the floor would be a permanently INCONCLUSIVE gate.
    floor = (ncpu * 0.10, ncpu * 0.125, ncpu * 0.113)
    check("dev1's MEASURED idle floor satisfies the policy",
          _quiescence(lambda: floor, 60)["established"],
          "thresholds must be reachable on the real host")


def _vm_entry(result: dict) -> dict:
    return [e for e in result["runners"] if e["name"] == "dev1-linux"][0]


def test_participation() -> None:
    print("\nparticipation is required, not assumed (§7)")
    check("a hook line is parsed from .env",
          host_gate.hook_from_env_text(
              "LANG=C\nACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/x/hook.sh\n") == "/opt/x/hook.sh")
    check("an .env without the hook yields None",
          host_gate.hook_from_env_text("LANG=C\nPATH=/usr/bin\n") is None)
    result = host_gate.verify_participation(host_gate.VmProbes())
    check("an unreachable VM is NOT counted as participating",
          not _vm_entry(result)["participating"])
    check("every registered runner is evaluated",
          len(result["runners"]) == len(host_gate_config.REGISTERED_RUNNERS)
          and len(result["runners"]) >= 3)
    check("the VM is one of them", any(e["kernel"] == "linux-vm" for e in result["runners"]))

    # A declared-but-absent hook must not count: the declaration is not the mechanism.
    declared_only = host_gate.verify_participation(host_gate.VmProbes(
        read_env=lambda p: "ACTIONS_RUNNER_HOOK_JOB_STARTED=/nope/missing.sh\n",
        check_exec=lambda p: False))
    check("a declared but non-executable hook is not participation",
          not _vm_entry(declared_only)["participating"])


def _listener_answers(runner: str) -> dict:
    """What `listener_started_after_env` answers under each of three timezones."""
    answers = {}
    for tz in ("UTC", "Europe/Stockholm", "America/Los_Angeles"):
        got = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,%r);import host_gate;"
             "print(host_gate.listener_started_after_env(%r))"
             % (str(HERE), runner)],
            capture_output=True, text=True, env={**os.environ, "TZ": tz}, timeout=120)
        answers[tz] = got.stdout.strip()
    return answers


def test_listener_freshness_is_timezone_independent() -> None:
    """Regression control for the false refusal of 2026-09-12 06:08.

    `listener_started_after_env` parsed `ps -o lstart=` with strptime/mktime. `ps` prints
    LOCAL time; `mktime` interprets in the PROCESS's timezone. A hook running inside a
    runner job without TZ set therefore read 21:19 CEST as 21:19 UTC -- two hours early --
    which put the listener before its own .env and reported a correctly-hooked runner as
    NOT participating. The SLO job refused itself.

    The answer must not depend on the caller's clock settings, so it is asked under two
    timezones two hours apart. Anything reading a formatted local timestamp fails this.
    """
    print("\nlistener freshness does not depend on the caller's timezone (regression)")
    runner = "/Users/mats/dev/actions-runner-mcp-re"
    if not Path(runner, ".env").exists():
        check("SKIPPED — this control needs the real runner install", True)
        return

    answers = _listener_answers(runner)
    check("every timezone gives the same answer", len(set(answers.values())) == 1, str(answers))
    check("and that answer is True for a listener started after its .env",
          set(answers.values()) == {"True"}, str(answers))


def unreadable_table() -> dict:
    raise OSError("ps unavailable")


def test_stopped_participants_are_quiet() -> None:
    print("\na stopped runner or VM is quiet; an unreachable one is not")
    root = "/Users/x/dev/actions-runner-dev1-fast-2"
    running = lambda: {7: (1, 5, f"{root}/bin/Runner.Listener run")}  # noqa: E731
    updated = lambda: {7: (1, 5, f"{root}/bin.2.337.0/Runner.Worker spawnclient")}  # noqa: E731
    other = lambda: {7: (1, 5, f"{root}-other/bin/Runner.Listener run")}  # noqa: E731
    check("a runner with no listener or worker is stopped", host_gate.runner_is_stopped(root, dict))
    check("a running listener is not stopped", not host_gate.runner_is_stopped(root, running))
    check("a worker from an updated bin.<version> dir is not stopped",
          not host_gate.runner_is_stopped(root, updated))
    check("another runner whose path extends this one does not count",
          host_gate.runner_is_stopped(root, other))
    check("an unreadable process table is not 'stopped'",
          not host_gate.runner_is_stopped(root, unreadable_table))

    stopped_vm = host_gate.verify_participation(host_gate.VmProbes(stopped=True))
    check("a VM Lima reports Stopped participates", _vm_entry(stopped_vm)["participating"])
    unreachable = host_gate.verify_participation(host_gate.VmProbes(stopped=False))
    check("a running-but-unreachable VM still does not",
          not _vm_entry(unreachable)["participating"])
