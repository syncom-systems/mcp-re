"""Reading the reducer's inputs as one snapshot.

The journal is O_APPEND and the ledger is replaced by rename, so each file is
individually consistent; the PAIR is a snapshot only if neither moved while both
were read. Nothing here sleeps or polls.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from journal_input_error import JournalInputError
from _reduce_model import problem


@dataclass(frozen=True)
class Inputs:
    """What one snapshot of the journal (and optional ledger) yielded."""
    journal_path: str
    rows: list
    reduced_bytes: bytes
    dropped_tail: int
    ledger: dict | None
    ledger_bytes: bytes | None
    ledger_usable: bool
    stable: bool
    problems: list


def _file_stat(path: str):
    """(size, mtime_ns) of a file, or None when absent. Module-level so a test can
    substitute it to simulate a writer landing between two reads."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return (st.st_size, st.st_mtime_ns)


def _read_bytes(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _snapshot(paths: list, live: bool) -> tuple:
    """Read every input inside one stat-before/stat-after window.

    Live: one bounded retry, then report instability rather than wait. Final
    audit: inputs are quiescent by definition, so movement is an input failure.
    """
    blobs: list = []
    for _ in range(2 if live else 1):
        before = [_file_stat(p) for p in paths]
        blobs = [_read_bytes(p) for p in paths]
        after = [_file_stat(p) for p in paths]
        if before == after:
            return blobs, True
    if not live:
        raise JournalInputError("input changed while it was being read: %s — a final "
                                "audit needs quiescent inputs (use --live for a running lane)"
                                % ", ".join(paths))
    return blobs, False


def _decode(raw: bytes, path: str, lineno: int):
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise JournalInputError("%s:%d: malformed JSONL record: %s" % (path, lineno, exc)) from exc


def _parse_line(raw: bytes, path: str, lineno: int):
    if not raw.strip():
        return None
    rec = _decode(raw, path, lineno)
    if not isinstance(rec, dict):
        raise JournalInputError("%s:%d: record is not a JSON object" % (path, lineno))
    return rec


def _present(rows: list) -> list:
    return [r for r in rows if r is not None]


def _parse_journal(data: bytes, path: str, live: bool) -> tuple:
    """Bytes -> (rows, reduced_bytes, dropped_tail_bytes).

    Tolerant of exactly one thing, and only under `--live`: a FINAL record with no
    terminating newline that does not parse, i.e. a writer caught mid-append.
    Everything else that does not parse is corruption and raises.
    """
    lines = data.split(b"\n")
    tail = lines.pop()               # b"" when the file ends with a newline
    rows = [_parse_line(raw, path, lineno) for lineno, raw in enumerate(lines, 1)]
    if not tail.strip():
        return _present(rows), data, 0
    try:
        rows.append(_parse_line(tail, path, len(lines) + 1))
    except JournalInputError:
        if not live:
            raise
        return _present(rows), data[:len(data) - len(tail)], len(tail)
    return _present(rows), data, 0


def _parse_ledger(data: bytes, path: str) -> dict:
    out: dict = {}
    for lineno, raw in enumerate(data.split(b"\n"), 1):
        rec = _parse_line(raw, path, lineno)
        if rec is not None:
            out[rec.get("id")] = rec
    return out


def _read_ledger(ldata: bytes | None, ledger_path: str, live: bool, stable: bool) -> tuple:
    """(ledger, ledger_usable, stable). A torn ledger read under `--live` is the
    same fact as a moving one, so it clears `stable`."""
    if not ledger_path or ldata is None:
        return None, False, stable
    try:
        return _parse_ledger(ldata, ledger_path), stable, stable
    except JournalInputError:
        if not live:
            raise
    return None, False, False


def _input_problems(dropped_tail: int, ledger_path: str, stable: bool) -> list:
    problems: list = []
    if dropped_tail:
        problems.append(problem("JNL-002", detail={"bytes_dropped": dropped_tail},
                                why="a writer was mid-append; the incomplete final record "
                                    "is excluded and the rest reduced"))
    if ledger_path and not stable:
        problems.append(problem(
            "LED-900", detail="journal/ledger pair changed during the read, after one retry",
            why="ledger cross-checks withheld: a transient state between two writes is not "
                "ledger corruption; re-run to audit a stable pair"))
    return problems


def read_inputs(log: str, ledger_path: str, live: bool) -> Inputs:
    """Snapshot, parse and report the input-level problems (JNL-002, LED-900)."""
    journal_path = log + ".jsonl"
    paths = [journal_path] + ([ledger_path] if ledger_path else [])
    blobs, stable = _snapshot(paths, live)
    ldata = blobs[1] if ledger_path else None
    rows, reduced_bytes, dropped_tail = _parse_journal(blobs[0] or b"", journal_path, live)
    ledger, usable, stable = _read_ledger(ldata, ledger_path, live, stable)
    return Inputs(journal_path, rows, reduced_bytes, dropped_tail, ledger, ldata, usable,
                  stable, _input_problems(dropped_tail, ledger_path, stable))
