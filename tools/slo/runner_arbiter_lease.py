"""`local-lease`: heavy work started by hand runs under the heavy-job locks."""

from __future__ import annotations

import os
import signal
import subprocess
import sys

import host_gate
import host_locks

#: Set in a leased command's environment. A wrapper that finds it (with a live pid) is
#: already inside a lease and must not take a second one -- that would wait on itself.
LEASE_ENV, LEASE_PID_ENV = "RUNNER_ARBITER_LEASE", "RUNNER_ARBITER_LEASE_PID"


def describe_holders(paths) -> str:
    """Who holds or queues for the host's locks, from the holder records."""
    out = []
    for h in host_locks.holders(paths["root"]):
        ident = h.get("identity") or {}
        what = ident.get("workflow_ref") or " ".join(ident.get("command") or []) or "?"
        out.append(f"{h.get('key')} [{h.get('plan')}] {what}")
    return "; ".join(out) or "no holder recorded"


def _forward_signals(child: subprocess.Popen) -> None:
    """SIGTERM/SIGHUP are passed on, and the lease ends when the child does. SIGINT is
    not: from a terminal the child already received it, and a second copy turns a
    graceful Bazel interrupt into a forced one."""
    def forward(signum, _frame) -> None:
        if child.poll() is None:
            child.send_signal(signum)
    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGHUP, forward)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def cmd_local_lease(paths, command: list[str]) -> int:
    """Run `command` holding the heavy lock set a dev1 CI job holds; release on exit.

    For heavy work started by hand on this host (a local `bazel test`), which otherwise
    runs beside a CI job the arbiter believes has the machine to itself. Waits -- saying
    for whom -- while a heavy job holds the slot, exactly as a queued CI job would.
    """
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("runner-arbiter local-lease: no command given", file=sys.stderr)
        return 2
    key = host_gate.local_lease_key()
    me = os.getpid()
    record = {"identity": {"runner": "local", "user": os.environ.get("USER", ""),
                           "command": command, "cwd": os.getcwd()}}

    def say_waiting() -> None:
        print(f"runner-arbiter: waiting for the heavy slot; held/queued: "
              f"{describe_holders(paths)}", file=sys.stderr, flush=True)

    if not host_locks.would_grant(paths["root"], "heavy", host_locks.EX):
        say_waiting()
    holder = host_gate.admit_local(paths, host_gate.Lease(key, me, record),
                                    on_wait=say_waiting)
    print(f"runner-arbiter: lease {key} admitted; running {' '.join(command)}",
          file=sys.stderr, flush=True)

    env = dict(os.environ)
    env[LEASE_ENV], env[LEASE_PID_ENV] = key, str(me)
    child = subprocess.Popen(command, env=env)
    _forward_signals(child)

    code = child.wait()
    holder.terminate()  # immediate release; the holder would also go when this process does
    return code if code >= 0 else 128 - code
