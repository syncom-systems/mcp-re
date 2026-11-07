"""Finding identity: the fingerprint, and reading the files and findings out of a prerun."""
from __future__ import annotations

import hashlib
import os
import re

_STOP = {
    "the", "a", "an", "is", "are", "be", "on", "of", "to", "in", "for", "and",
    "or", "not", "no", "but", "with", "vs", "it", "its", "as", "at", "by", "via",
    "that", "this", "from", "into", "only", "any", "all", "can", "could", "may",
    "when", "if", "then", "than", "so", "a", "per", "each", "both",
}


def _basename(file_or_loc):
    """File basename from a `module`/`location` string (strips `:line`, dirs)."""
    s = (file_or_loc or "").split(":")[0].strip()
    return os.path.basename(s) if s else ""


def _norm_tokens(title):
    toks = re.findall(r"[a-z0-9]+", (title or "").lower())
    toks = [t for t in toks if t not in _STOP and len(t) > 1]
    return sorted(set(toks))


def fingerprint(file_or_loc, title):
    base = _basename(file_or_loc)
    key = base + "|" + " ".join(_norm_tokens(title))
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def _findings_of(prerun):
    """Accept several prerun shapes; return a list of finding dicts."""
    if isinstance(prerun, list):
        return prerun
    for k in ("rawFindings", "findings"):
        if isinstance(prerun.get(k), list):
            return prerun[k]
    # 06-14 shape: act_now / defer buckets.
    buckets = (prerun.get(k) for k in ("act_now", "defer"))
    return [item for v in buckets if isinstance(v, list) for item in v]


def _location_of(f):
    """The finding's full repo-relative path, without any `:line`."""
    return (f.get("location") or f.get("module") or f.get("file") or "").split(":")[0].strip()


def _file_of(f):
    return _basename(f.get("location") or f.get("module") or f.get("file") or "")
