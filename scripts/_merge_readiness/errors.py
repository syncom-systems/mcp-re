# SPDX-License-Identifier: Apache-2.0
"""The gate's one exception."""

from __future__ import annotations


class Undecidable(Exception):
    """The gate cannot answer. Never the same thing as NOT_READY, and never merged on."""
