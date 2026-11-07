# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict on the real tree."""

from __future__ import annotations

from _verification_trigger.config import CONTROL_PATHS, PROBE_MAX_TIMEOUT_MINUTES, PROBE_MAX_UNITS

import _affected
from _manifest import ManifestError
from workflow_reader import WorkflowSyntaxError

from _verification_trigger.gate import all_failures, fingerprint_inputs, read_texts


def _summary(texts: dict[str, str]) -> str:
    return (
        f"verification-trigger gate: OK — verification.yml starts only on schedule and dispatch; "
        f"{len(CONTROL_PATHS)} control paths start no complete run from a pull request or push; "
        f"the bounded probe has a pull-request filter, a {PROBE_MAX_TIMEOUT_MINUTES}-minute timeout "
        f"and a {PROBE_MAX_UNITS}-unit cap; pre-merge starts on every pull request and "
        f"post-merge calls it; {len(texts)} workflows checked for indirect starts"
    )


def _report_failures(failures: list[str]) -> int:
    print("verification-trigger gate: FAILED")
    for failure in sorted(set(failures)):
        print(f"  - {failure}")
    return 1


def judge() -> int:
    try:
        required = fingerprint_inputs()
        texts = read_texts()
        failures = all_failures(texts, _affected.platform_change, required)
    except ManifestError as exc:
        print(f"verification-trigger gate: FAILED — the manifest does not load: {exc}")
        return 1
    except (WorkflowSyntaxError, KeyError) as exc:
        print(f"verification-trigger gate: FAILED — a workflow cannot be read: {exc!r}")
        return 1
    if not required:
        print("verification-trigger gate: FAILED — the fingerprint read set is empty")
        return 1
    if failures:
        return _report_failures(failures)
    print(_summary(texts))
    return 0
