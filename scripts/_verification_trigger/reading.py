# SPDX-License-Identifier: Apache-2.0
"""Cached workflow parsing and the trigger and job-scalar questions asked of it."""

from __future__ import annotations

import functools

import workflow_reader
from workflow_reader import Mapping, Scalar, glob_matches

#: The reader is a line parser over files of several hundred lines, and the selftest reads each
#: workflow once per control, so a text is parsed once.
parse = functools.lru_cache(maxsize=None)(workflow_reader.parse)
parse_yaml = functools.lru_cache(maxsize=None)(workflow_reader.parse_yaml)


def starts_on(text: str, event: str, path: str) -> bool:
    """Whether a `path` change delivered by `event` starts the workflow `text`, by GitHub's
    rule: the trigger exists and has no path filter, or a filter matching the path."""
    trigger = parse(text).triggers.get(event)
    if trigger is None:
        return False
    if trigger.paths is None:
        return True
    return any(glob_matches(pattern, path) for pattern in trigger.paths)


def job_scalar(text: str, job: str, key: str) -> str | None:
    jobs = parse_yaml(text).get("jobs")
    body = jobs.get(job) if isinstance(jobs, Mapping) else None
    node = body.get(key) if isinstance(body, Mapping) else None
    return node.value if isinstance(node, Scalar) else None


def job_uses(text: str, key: str) -> str | None:
    return job_scalar(text, key, "uses")
