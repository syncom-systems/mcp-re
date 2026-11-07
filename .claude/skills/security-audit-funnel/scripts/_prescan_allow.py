"""Allowlist of the structural pre-scan: an inline `prescan-allow: <kind>` marker on
the offending line, or a JSON file mapping kind -> substrings to suppress."""

import json
import re


def load_allow(args):
    allow = {}
    if "--allow" in args:
        try:
            with open(args[args.index("--allow") + 1], encoding="utf-8") as fh:
                allow = json.load(fh)
        except (OSError, ValueError, IndexError):
            allow = {}
    return allow


def _inline_allows(kind, line):
    if not line or "prescan-allow" not in line:
        return False
    return bool(re.search(r"prescan-allow:\s*" + re.escape(kind), line)
                or "prescan-allow: all" in line)


class Allowlist:
    """Suppressions loaded from the --allow file: kind -> substrings (a file path
    fragment or an exact symbol)."""

    def __init__(self, entries):
        self._entries = entries

    def allows(self, kind, rel, symbol, line):
        if _inline_allows(kind, line):
            return True
        return any(needle and (needle in rel or needle == symbol)
                   for needle in self._entries.get(kind, []))
