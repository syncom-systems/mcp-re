#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral closure gate — the local gate may not reach a cloud.

THE RULE. The execution closure of `scripts/local_gate.sh --with-kind` is provider-neutral:
no AWS, GCP or Azure CLI, no provider account, project or registry discovery, and no cloud
credential. Provider provisioning lives in drivers the local path does not reach.

THE FAILURE IT EXISTS FOR. The fleet harness ran `gcloud config get-value project` for every
substrate, kind included, behind `|| true`. A PATH tripwire caught it at run time, which is a
second control and stays one. Putting the line behind `if PROVIDER=gke` would have made the
symptom go away and left the design as it was: one script holding provisioning AND proofs,
where the next provider line is one edit away from the local path. So the harness was split
(docs/security/fleet-proofs-core.sh, -kind.sh, gke-multi-replica-validation.sh), and this
gate is what keeps the split true.

WHAT IT READS. The closure is every repository script reachable from `scripts/local_gate.sh`
by invocation, followed through shell scripts (any repository path in a command segment that
is not a message — `echo`, `printf`, `log`, `fail`, `verdict` — counts, whether in command
position or as an argument to `bash`, `python3`, `exec`, `timeout` and the like) and through
Python files (paths passed to `subprocess`/`os` process calls, and modules imported from the
directories this repository's scripts import from). Comments are never callers.

Over-approximating the closure is the safe direction for a prohibition: an extra file scanned
can only produce a refusal, never a pass. The required-members check is the other direction:
the files that MUST be in the closure (the kind driver, the proof core, the Job-spec
rehearsal) are asserted present, so a parse change cannot shrink the closure into a vacuous
pass, and the cloud driver is asserted absent.

WHAT IT REFUSES, inside that closure:
  * a provider CLI in command position (also after `$(`, a backtick, `exec`, `command`,
    `env`, `xargs`, `timeout N`, `if`/`then`/`!` …) or probed with `command -v`/`which`/`type`,
    and a provider CLI as a quoted literal (a `subprocess` argv inside a heredoc);
  * in Python: a provider CLI as the program of a process call or `shutil.which`, an import
    of a cloud SDK, a credential environment read;
  * a cloud credential variable, and a provider registry host, in shell code.
A guard does not exempt anything: a provider call behind `if [[ $PROVIDER == gke ]]` in a
closure file is still in the closure.

WHAT IT DOES NOT PROVE. What a `bazel run`/`bazel test` target does at run time — Rust is
opaque to a text gate. The runtime PATH tripwires are the independent control for that.

Run:  python3 scripts/provider_neutral_closure_gate.py
      python3 scripts/provider_neutral_closure_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _provider_neutral.cli import judge  # noqa: E402
from _provider_neutral.closure import adjudicate, analyse, read_repo  # noqa: E402,F401
from _provider_neutral.config import ENTRY, REPO  # noqa: E402,F401
from _provider_neutral.pysrc import python_findings_and_edges  # noqa: E402,F401
from _provider_neutral.selftest import selftest  # noqa: E402,F401
from _provider_neutral.shell import shell_findings_and_edges  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return judge()


if __name__ == "__main__":
    sys.exit(main())
