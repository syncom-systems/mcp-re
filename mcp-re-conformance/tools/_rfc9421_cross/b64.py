# SPDX-License-Identifier: Apache-2.0
"""Unpadded base64url."""

from __future__ import annotations

import base64


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
