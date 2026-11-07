# SPDX-License-Identifier: Apache-2.0
"""Prove the gate can FAIL: injected provider calls are refused, messages, comments and data tables are not callers."""

from __future__ import annotations

from _provider_neutral.closure import adjudicate
from _provider_neutral.config import ENTRY
from _provider_neutral.selftest_data import BASE_TREE, CORE, CORE_REFUSALS, PYTHON_REFUSALS

_KIND_DRIVER = "docs/security/fleet-proofs-kind.sh"
_CLOUD_DRIVER = "docs/security/gke-multi-replica-validation.sh"


def _refused(path: str, text: str, needle: str) -> None:
    tree = dict(BASE_TREE)
    tree[path] = tree.get(path, "#!/bin/bash\n") + text
    _, found = adjudicate(tree)
    assert any(needle in p for p in found), (text, found)


def _check_clean_tree() -> None:
    closure, problems = adjudicate(BASE_TREE)
    assert problems == [], problems
    assert "docs/security/sel.py" in closure and _CLOUD_DRIVER not in closure


def _check_transitive_provider() -> None:
    """A NEW script reached from the closure that calls a provider."""
    tree = dict(BASE_TREE, **{"tools/new_helper.sh": "#!/bin/bash\naws ecr get-login-password\n"})
    tree[CORE] += '"$REPO_ROOT/tools/new_helper.sh" --flag\n'
    assert any(p.startswith("tools/new_helper.sh: provider CLI invoked") for p in adjudicate(tree)[1])


def _check_python_refusals() -> None:
    """Python reached from the closure: a provider process, a cloud SDK, a credential read."""
    for snippet, needle in PYTHON_REFUSALS:
        tree = dict(BASE_TREE)
        tree["docs/security/sel.py"] = snippet
        assert any(needle in p for p in adjudicate(tree)[1]), snippet


def _check_cloud_driver() -> None:
    """Reaching the cloud driver is itself refused, even with no other finding."""
    tree = dict(BASE_TREE)
    tree[_KIND_DRIVER] += f"{_CLOUD_DRIVER} --teardown\n"
    assert any("cloud driver is reachable" in p for p in adjudicate(tree)[1])


def _check_lost_member() -> None:
    """A closure that lost a required member is not a pass."""
    tree = dict(BASE_TREE)
    tree[ENTRY] = "#!/bin/bash\ntools/slo/rehearse_job_spec.sh\n"
    assert any("fleet-proofs-kind.sh: REQUIRED" in p for p in adjudicate(tree)[1])


def selftest() -> int:
    _check_clean_tree()
    for text, needle in CORE_REFUSALS:
        _refused(CORE, text, needle)
    _check_transitive_provider()
    _check_python_refusals()
    _check_cloud_driver()
    _check_lost_member()
    print("provider-neutral closure gate selftest: OK (injected provider calls refused; messages, comments "
          "and data tables are not callers)")
    return 0
