# SPDX-License-Identifier: Apache-2.0
"""The toolchain lock: the one reader of `verification/policy/toolchains.lock.toml`.

The lock pins every tool identity a lane, a gate or an installer depends on. Its readers
are of three kinds, and all of them read it here:

  * the assurance tooling, through `_toolchain_lock.load_toolchains`, which adds the extraction
    container's identity and artifact checks on top of `load`;
  * the gates that hold a support claim to its runtime pin (`node_runtime_gate.py`,
    `python_runtime_gate.py`) and the extraction-image gate, through `load` and
    `interpreters`;
  * the installers, which run before any environment is prepared: the Python ones import
    this module, and the shell ones ask the CLI below.

`interpreters` is the one statement of what a runtime pin must look like — resolved, every
entry an exact `major.minor.patch`, and one pinned version per support line — so the two
runtime gates refuse the same malformed pin with the same sentence, and the installers
prepare exactly the set those gates checked.

Stdlib only, at import and when run: the shell installers call it with whatever `python3`
the runner has before any repository environment exists.

Run:  python3 tools/verification/_toolchains.py interpreters <ecosystem>
      python3 tools/verification/_toolchains.py --selftest
"""

from __future__ import annotations

import sys

from _registries import ManifestError
from _toolchains_pins import ECOSYSTEMS, interpreters, pin_shape_cases  # noqa: F401 — public API
from _toolchains_read import STATES, WHERE, load, path, unresolved_pins  # noqa: F401 — public API
from _toolchains_selftest import selftest


def _print_interpreters(ecosystem: str) -> int:
    try:
        lock = load()
    except ManifestError as exc:
        print(f"toolchain lock: {exc}", file=sys.stderr)
        return 1
    pinned, why = interpreters(lock.get(ecosystem), ecosystem)
    if why is not None:
        print(f"toolchain lock: {why}", file=sys.stderr)
        return 1
    print("\n".join(sorted(pinned.values())))
    return 0


def _asks_for_interpreters(argv: list[str]) -> bool:
    return len(argv) == 2 and argv[0] == "interpreters" and argv[1] in ECOSYSTEMS


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if _asks_for_interpreters(argv):
        return _print_interpreters(argv[1])
    print(
        "usage: _toolchains.py interpreters {" + ",".join(ECOSYSTEMS) + "} | --selftest",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
