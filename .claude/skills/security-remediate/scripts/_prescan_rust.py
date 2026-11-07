"""Rust analyzer (role-aware): per-file structural checks, then the per-crate serve
and verify aggregation."""

import os
import re
from dataclasses import dataclass, field

from _prescan_crate import find_crate_root
from _prescan_rust_text import (
    enclosing_fn, line_of, line_text, mask_const_eval)
from _prescan_sink import Sink
from _prescan_vocab import (
    RS_NOOP_CTOR, RS_PANIC, RS_SEC_IMPL, RS_SERVE, RS_STUB, RS_UNSAFE,
    RS_VERIFY, SECURITY_HINT)

_CONSTRUCTOR = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\s*(::new\b|\{)")


@dataclass
class _Scan:
    sink: Sink
    crates: dict
    lib_impls: dict = field(default_factory=dict)       # symbol -> file
    prod_ctor_refs: set = field(default_factory=set)    # constructed in prod


def _is_serving_unit(info):
    return info["is_bin"] or info["is_demo"]


def _note_crate(info, src, rel):
    if not info:
        return
    if RS_SERVE.search(src):
        info["has_serve"] = True
        info["serve_file"] = info["serve_file"] or rel
    if RS_VERIFY.search(src):
        info["has_verify"] = True


def _report_stubs(path, src, sink):
    for m in RS_STUB.finditer(src):
        sink.add("stub-body", "block", enclosing_fn(src, m.start()), path,
                 line_of(src, m.start()),
                 f"Production code contains `{m.group(1)}` — an unimplemented "
                 "contract on a shipped path; a consumer reaching it panics.")


def _report_unsafe(path, src, rel, sink):
    for m in RS_UNSAFE.finditer(src):
        sym, lt = enclosing_fn(src, m.start()), line_text(src, m.start())
        if sink.allows("unsafe", rel, sym, lt):
            continue
        sink.add("unsafe-block", "block", sym, path, line_of(src, m.start()),
                 "`unsafe` in production without an allowlist entry — requires an "
                 "explicit memory-safety justification (`// prescan-allow: unsafe`).")


def _report_panics(path, src, rel, sink):
    scan = mask_const_eval(src)
    panics = [m for m in RS_PANIC.finditer(scan)
              if not sink.allows("panic", rel, enclosing_fn(src, m.start()),
                                 line_text(src, m.start()))]
    if panics:
        sink.add("panic-in-security-path", "block", os.path.basename(path), path,
                 line_of(src, panics[0].start()),
                 f"{len(panics)} non-allowlisted panicking call(s) "
                 "(unwrap/expect/panic!/assert!) in a security-relevant production "
                 "file. A panic on untrusted input is a denial-of-service; convert "
                 "to a fail-closed error or allowlist a proven-infallible call.")


def _note_security_impls(path, src, scan):
    for m in RS_SEC_IMPL.finditer(src):
        scan.lib_impls.setdefault(m.group(2), path)
    for m in _CONSTRUCTOR.finditer(src):
        scan.prod_ctor_refs.add(m.group(1))


def _report_noop_wiring(path, src, rel, sink):
    for m in RS_NOOP_CTOR.finditer(src):
        sym, lt = m.group(1), line_text(src, m.start())
        if not SECURITY_HINT.search(sym) or sink.allows("noop-in-binary", rel, sym, lt):
            continue
        sink.add("noop-in-binary", "block", sym, path, line_of(src, m.start()),
                 "A reference/no-op security implementation is wired in a binary's "
                 "composition root — confirm it is not standing in for a real "
                 "verifier/resolver/policy on a production request path.")


def _wires_noops(role, info):
    return role in ("binary", "comproot") and info and _is_serving_unit(info)


def _scan_file(entry, scan):
    path, src, role, crate_root = entry
    sink = scan.sink
    rel = os.path.relpath(path, sink.root)
    info = scan.crates.get(crate_root)
    _note_crate(info, src, rel)
    _report_stubs(path, src, sink)
    _report_unsafe(path, src, rel, sink)
    if SECURITY_HINT.search(rel):
        _report_panics(path, src, rel, sink)
    _note_security_impls(path, src, scan)
    if _wires_noops(role, info):
        _report_noop_wiring(path, src, rel, sink)


def _report_unconstructed(scan):
    """Advisory: a security impl in a LIBRARY crate constructed nowhere in-repo."""
    for sym, path in sorted(scan.lib_impls.items()):
        info = scan.crates.get(find_crate_root(path))
        if info and _is_serving_unit(info):
            continue
        if sym not in scan.prod_ctor_refs:
            scan.sink.add(
                "unconstructed-impl", "warn", sym, path, None,
                "A security trait impl is never constructed in this repo. In a "
                "library this is usually fine (downstream consumers construct it); "
                "confirm it is not dead code or a forgotten wiring.")


def _report_serving_crate(crate_root, info, sink):
    loc = os.path.join(sink.root,
                       info["serve_file"] or os.path.relpath(crate_root, sink.root))
    if not info["has_verify"]:
        sink.add("serve-without-verify", "block", info["name"], loc, None,
                 "A serving binary/demo accepts connections (TcpListener/serve/"
                 "accept) but no verification/authorization/binding call was found "
                 "in the crate — the Rust analogue of an HTTP app with no auth. If "
                 "this is an intentionally-unverified inner server behind the proxy, "
                 "allowlist it (serve-without-verify).")
    else:
        sink.add("verify-manual-verify", "warn", info["name"], loc, None,
                 "Serving surface and a verification call both exist, but Stage 1 "
                 "cannot prove the verify gate is on every request path and "
                 "unbypassable. Stage 2 must confirm.")


def _report_serving_crates(scan):
    """A serving binary/demo crate with no verification call anywhere in it BLOCKs."""
    for crate_root, info in sorted(scan.crates.items()):
        if not info["has_serve"] or not _is_serving_unit(info):
            continue
        if scan.sink.allows("serve-without-verify", info["name"], info["name"], ""):
            continue
        _report_serving_crate(crate_root, info, scan.sink)


def rust_pass(rs_files, crates, sink):
    """rs_files: list of (path, prod_src, role, crate_root). Per-file structural
    checks now; per-crate serve/verify aggregated after."""
    scan = _Scan(sink, crates)
    for entry in rs_files:
        _scan_file(entry, scan)
    _report_unconstructed(scan)
    _report_serving_crates(scan)
