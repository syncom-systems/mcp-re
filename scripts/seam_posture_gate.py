#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seam-posture gate — every optional capability states ON or OFF at startup.

WHAT THIS PROVES, exactly: every variant of `startup_posture::Seam` appears in
`Seam::ALL`, and every variant is passed to `posture.declare(Seam::<X>, ..)` exactly once
in `app.rs` or a stage module under `app/` -- by a literal `posture.declare(Seam::X, ..)` or by
`install_capability(start.stating(Seam::X), ..)`, which consumes an `Established` and declares the
seam it names. An `Established` split by `into_parts` must declare the state half it yields.
That is a syntactic check over the source of those
modules, and the claim stops there.

WHAT IT DOES NOT PROVE: that the declared state is the RIGHT one, that the ON and OFF
lines say anything useful, or that the branch producing them matches what was actually
wired. Two of those are already covered elsewhere and better:

  - `PostureLog::declare` takes a `SeamState` BY VALUE, so a decision written as an `if`
    must produce one on both arms. The OFF branch is a type obligation, not a convention,
    and no gate is needed for it.
  - `PostureLog::assert_complete` refuses startup — in every build profile — when a seam
    went unstated. That is the runtime backstop, and it is strictly stronger than this
    gate where it runs.

WHY THIS GATE EXISTS ANYWAY: `assert_complete` only fires on a startup that actually
reaches the posture phase, and no HERMETIC configuration does — the phase sits after the
replay tier is established, and every replay tier that validation accepts needs a live
Redis or etcd. So in `cargo test --workspace` and `bazel test //...`, the runtime check
is never reached. A seam added without a declaration would therefore ship green and only
be caught by the Redis-gated lane. This gate is what makes the omission loud in every
lane.

WHY IT MATTERS. ADR-MCPRE-056 §5.4: an operator reading a startup transcript cannot
distinguish "this capability is off in this deployment" from "this build does not have
this capability" when a seam is silent. Those call for different responses — set a flag
versus replace the binary — and the cost of guessing wrong is that a security control
stays off. Four seams (verified-context carrier, online OCSP, MCP transport contract,
admission currency) announced only when enabled before §5.4 landed.

Run:  python3 scripts/seam_posture_gate.py
      python3 scripts/seam_posture_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

POSTURE_MODULE = "mcp-re-proxy/src/startup_posture.rs"
# The enum may live in a child module of the posture module — one type per file. The gate
# reads the whole module, not one file of it: a gate anchored on a path rather than on the
# declaration stops measuring the moment the type is moved, and reports that as a crash
# rather than as a pass, which is why this is the correction and not a skip.
POSTURE_MODULE_DIR = "mcp-re-proxy/src/startup_posture"
# The composition root. Declarations live at the decision sites, which are all here.
# Its stage modules under `app/` hold decision sites too, so they are read with it.
DECLARING_MODULE = "mcp-re-proxy/src/app.rs"
DECLARING_MODULE_DIR = "mcp-re-proxy/src/app"

# `    SecurityAuditRecord,` inside `pub enum Seam { .. }`.
ENUM_BLOCK = re.compile(r"pub enum Seam \{(.*?)\n\}", re.S)
ENUM_VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9]*),\s*$", re.M)

# `    pub const ALL: &'static [Seam] = &[ .. ];`
ALL_BLOCK = re.compile(r"const ALL: &'static \[Seam\] = &\[(.*?)\];", re.S)
ALL_ENTRY = re.compile(r"Seam::([A-Z][A-Za-z0-9]*)")

# `posture.declare(Seam::OnlineOcspClientRevocation, ocsp_state);`
DECLARE_CALL = re.compile(r"\.declare\(\s*Seam::([A-Z][A-Za-z0-9]*)")

# `install_capability(start.stating(Seam::AdmissionCurrency), proxy, established, attach)`: the
# composition root's one operation that consumes an `Established<T>`, attaches the artifact
# when ON and declares the posture of the seam NAMED in the call. It states that seam's
# posture exactly as a literal `.declare(Seam::X, ..)` does, so it counts as one.
INSTALL_CALL = re.compile(r"\binstall_capability\(\s*\w+\.stating\(\s*Seam::([A-Z][A-Za-z0-9]*)\s*\)")

# The five production installation paths, each seam with the ONE producer that establishes
# it and the ONE attachment that consumes its artifact: seam -> (producer, attachment).
# Completeness and uniqueness above cannot see two valid installs swapped; this table can.
CAPABILITY_MAP = {
    "SecurityAuditRecord": ("audit_posture", "with_audit_posture"),
    "EvidenceRetention": ("evidence_retention", "with_evidence_retention"),
    "VerifiedContextCarrier": ("verified_context_carrier", "with_verified_context_carrier"),
    "MrtrContinuationStore": ("mrtr_continuation_store", "with_continuation_store"),
    "AdmissionCurrency": ("admission_currency", "with_admission_enforcer"),
}
PRODUCER_CALL = re.compile(r"serving_capabilities::(\w+)\s*\(")
ATTACH_NAME = re.compile(r"\bwith_\w+")

# `let (artifact, state) = established.into_parts();` -- the two bindings.
SPLIT = re.compile(r"let\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=[^;]*?\.into_parts\(\)\s*;", re.S)


def _find(pattern: re.Pattern[str], text: str, what: str, path: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"seam-posture gate: cannot find {what} in {path}")
    return match.group(1)


def _all_failures(variants: list[str], listed: list[str]) -> list[str]:
    """`Seam::ALL` drives the runtime completeness check, so a variant missing from it is
    invisible to `assert_complete` as well as to this gate."""
    failures = [
        f"Seam::{variant} is not in Seam::ALL, so nothing checks that it is "
        f"ever declared ({POSTURE_MODULE})"
        for variant in variants
        if variant not in listed
    ]
    failures += [
        f"Seam::ALL lists Seam::{name}, which is not a variant"
        for name in listed
        if name not in variants
    ]
    return failures


def _declaration_failures(variants: list[str], declared: list[str]) -> list[str]:
    failures: list[str] = []
    for variant in variants:
        count = declared.count(variant)
        if count == 0:
            failures.append(
                f"Seam::{variant} is never declared in {DECLARING_MODULE}: an operator "
                f"cannot tell whether the capability is off or absent from this build. "
                f"Add `posture.declare(Seam::{variant}, ..)` with a SeamState on BOTH "
                f"branches of the decision."
            )
        elif count > 1:
            failures.append(
                f"Seam::{variant} is declared {count} times in {DECLARING_MODULE}: the "
                f"transcript states one capability's posture more than once, and a "
                f"reader has no way to know which line governs."
            )
    failures += [
        f"{DECLARING_MODULE} declares Seam::{name}, which is not a Seam variant"
        for name in set(declared) - set(variants)
    ]
    return failures


def _disconnected_failures(source: str) -> list[str]:
    """An `Established` split by `into_parts` must declare the posture half it yields.

    The pair is the point of `Established`: if the state half is bound and never handed to
    a `declare`, the artifact is installed under no stated posture, or the posture is
    stated from some other value. `install_capability` is the one place that splits and
    declares in the same body; any other split must declare its own state binding.
    """
    failures: list[str] = []
    for match in SPLIT.finditer(source):
        state = match.group(2)
        tail = source[match.end():]
        end = re.search(r"\n\s*(?:pub(?:\([^)]*\))?\s+)?fn ", tail)
        body = tail[: end.start()] if end else tail
        if not re.search(rf"\.declare\([^;]*?\b{state}\b\s*\)", body, re.S):
            failures.append(
                f"an Established is split into (_, {state}) and `{state}` is never "
                f"declared in the same function: the artifact and its posture are "
                f"disconnected. Use install_capability(start.stating(Seam::..), ..) or declare "
                f"`{state}` beside the split."
            )
    return failures


def _install_calls(source: str) -> list[tuple[str, str | None, str | None]]:
    """Each `install_capability(..)` call as (seam, producer, attachment).

    The producer is the last `serving_capabilities::<name>(` before the call; the attachment
    is the first `with_*` name after the third argument (a closure's parameter commas included).
    """
    calls = []
    prev_end = 0
    for match in INSTALL_CALL.finditer(source):
        start = source.index("(", match.start())
        depth, args, arg_start, end = 0, [], start + 1, len(source)
        for i in range(start, len(source)):
            c = source[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    args.append(source[arg_start:i])
                    end = i
                    break
            elif c == "," and depth == 1:
                args.append(source[arg_start:i])
                arg_start = i + 1
        producers = PRODUCER_CALL.findall(source[prev_end:match.start()])
        attach = ATTACH_NAME.search(",".join(args[3:])) if len(args) > 3 else None
        calls.append((
            match.group(1),
            producers[-1] if producers else None,
            attach.group(0) if attach else None,
        ))
        prev_end = end
    return calls


def _correspondence_failures(
    source: str, expected: dict[str, tuple[str, str]]
) -> list[str]:
    """Each mapped seam is installed through its own producer and its own attachment."""
    failures: list[str] = []
    calls = _install_calls(source)
    for seam, (producer, attach) in expected.items():
        if not any(c[0] == seam for c in calls):
            failures.append(
                f"Seam::{seam} is not installed through install_capability: its "
                f"producer `{producer}` and attachment `{attach}` are unchecked."
            )
    for seam, got_producer, got_attach in calls:
        if seam not in expected:
            continue
        producer, attach = expected[seam]
        if got_producer != producer:
            failures.append(
                f"Seam::{seam} is installed from producer `{got_producer}`, expected "
                f"`{producer}`: the posture stated is not the one the artifact has."
            )
        if got_attach != attach:
            failures.append(
                f"Seam::{seam} attaches through `{got_attach}`, expected `{attach}`."
            )
    return failures


def _production(text: str) -> str:
    """A file without its trailing `#[cfg(test)]` region: a test that calls the installer
    states no deployment's posture, so it must not count as a declaration."""
    return text.split("#[cfg(test)]", 1)[0]


def _module_source(root: Path, module: str, module_dir: str) -> str:
    """A module's root file followed by its direct children, as one text."""
    source = _production((root / module).read_text(encoding="utf-8"))
    for child in sorted((root / module_dir).glob("*.rs")):
        source += _production(child.read_text(encoding="utf-8"))
    return source


def check(root: Path, expected: dict[str, tuple[str, str]] | None = None) -> list[str]:
    """Return a list of failures; empty means the gate passes."""
    for path in (root / POSTURE_MODULE, root / DECLARING_MODULE):
        if not path.is_file():
            return [f"missing {path.relative_to(root)}"]

    posture_src = _module_source(root, POSTURE_MODULE, POSTURE_MODULE_DIR)
    declaring_src = _module_source(root, DECLARING_MODULE, DECLARING_MODULE_DIR)

    variants = ENUM_VARIANT.findall(
        _find(ENUM_BLOCK, posture_src, "`pub enum Seam`", POSTURE_MODULE)
    )
    listed = ALL_ENTRY.findall(
        _find(ALL_BLOCK, posture_src, "`Seam::ALL`", POSTURE_MODULE)
    )
    declared = DECLARE_CALL.findall(declaring_src) + INSTALL_CALL.findall(declaring_src)

    failures: list[str] = _disconnected_failures(declaring_src)
    failures += _correspondence_failures(
        declaring_src, CAPABILITY_MAP if expected is None else expected
    )
    if not variants:
        failures.append(f"`pub enum Seam` in {POSTURE_MODULE} has no variants")
    return failures + _all_failures(variants, listed) + _declaration_failures(variants, declared)


_SELFTEST_POSTURE = """\
pub enum Seam {
    Alpha,
    Beta,
}

impl Seam {
    pub const ALL: &'static [Seam] = &[
        Seam::Alpha,
        Seam::Beta,
    ];
}
"""


def _selftest_tree(tmp: Path, declaring: str) -> Path:
    root = tmp / "tree"
    (root / "mcp-re-proxy" / "src").mkdir(parents=True)
    (root / POSTURE_MODULE).write_text(_SELFTEST_POSTURE, encoding="utf-8")
    (root / DECLARING_MODULE).write_text(declaring, encoding="utf-8")
    return root


_SELFTEST_CASES: list[tuple[str, str, str | None]] = [
    (
        "one seam installed and one declared",
        "install_capability(start.stating(Seam::Alpha), proxy, est, attach);\n"
        "posture.declare(Seam::Beta, b);\n",
        None,
    ),
    (
        "a seam installed twice",
        "install_capability(start.stating(Seam::Alpha), proxy, est, attach);\n"
        "install_capability(start.stating(Seam::Alpha), proxy, est, attach);\n"
        "posture.declare(Seam::Beta, b);\n",
        "Seam::Alpha is declared 2 times",
    ),
    (
        "a seam both installed and declared",
        "install_capability(start.stating(Seam::Alpha), proxy, est, attach);\n"
        "posture.declare(Seam::Alpha, a);\n"
        "posture.declare(Seam::Beta, b);\n",
        "Seam::Alpha is declared 2 times",
    ),
    (
        "an installation naming no variant",
        "install_capability(start.stating(Seam::Alpha), proxy, est, attach);\n"
        "posture.declare(Seam::Beta, b);\n"
        "install_capability(start.stating(Seam::Gamma), proxy, est, attach);\n",
        "which is not a Seam variant",
    ),
    (
        "a seam whose only installation is missing",
        "posture.declare(Seam::Alpha, a);\n",
        "Seam::Beta is never declared",
    ),
    (
        "an Established split whose state is never declared",
        "fn f() {\n    let (artifact, state) = est.into_parts();\n"
        "    proxy.attach(artifact);\n}\n"
        "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Beta, b);\n",
        "disconnected",
    ),
    (
        "an Established split whose state is declared",
        "fn f() {\n    let (artifact, state) = est.into_parts();\n"
        "    posture.declare(Seam::Alpha, state);\n}\n"
        "posture.declare(Seam::Beta, b);\n",
        None,
    ),
    (
        "both seams declared",
        "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Beta, b);\n",
        None,
    ),
    (
        "a declaration inside a test region is not a declaration",
        "posture.declare(Seam::Alpha, a);\n#[cfg(test)]\nmod t { fn f() {\n"
        "posture.declare(Seam::Beta, b);\n} }\n",
        "Seam::Beta is never declared",
    ),
    (
        "a seam that is never declared",
        "posture.declare(Seam::Alpha, a);\n",
        "Seam::Beta is never declared",
    ),
    (
        "a seam declared twice",
        "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Alpha, a2);\n"
        "posture.declare(Seam::Beta, b);\n",
        "Seam::Alpha is declared 2 times",
    ),
    (
        "a declaration naming no variant",
        "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Beta, b);\n"
        "posture.declare(Seam::Gamma, g);\n",
        "which is not a Seam variant",
    ),
]


def _verdict(name: str, failures: list[str], expected: str | None) -> bool:
    ok = not failures if expected is None else any(expected in f for f in failures)
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"        expected {expected!r}, got {failures}")
    return ok


def _selftest_variant_missing_from_all() -> bool:
    # A variant absent from ALL is checked against the real enum shape rather than the
    # fixture, because the fixture's ALL is what the other cases keep honest.
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw) / "tree"
        (root / "mcp-re-proxy" / "src").mkdir(parents=True)
        (root / POSTURE_MODULE).write_text(
            _SELFTEST_POSTURE.replace("        Seam::Beta,\n", ""), encoding="utf-8"
        )
        (root / DECLARING_MODULE).write_text(
            "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Beta, b);\n",
            encoding="utf-8",
        )
        return _verdict("a variant missing from Seam::ALL", check(root, {}), "not in Seam::ALL")


_MAP = {"Alpha": ("prod_a", "with_a"), "Beta": ("prod_b", "with_b")}


def _install(seam: str, producer: str, attach: str) -> str:
    return (
        f"let established = crate::serving_capabilities::{producer}(cfg)?;\n"
        f"proxy = install_capability(start.stating(Seam::{seam}), proxy, established, "
        f"|p, a| p.{attach}(a));\n"
    )


_CORRESPONDENCE_CASES: list[tuple[str, str, str | None]] = [
    ("correct producer, seam and attachment",
     _install("Alpha", "prod_a", "with_a") + _install("Beta", "prod_b", "with_b"), None),
    ("wrong producer",
     _install("Alpha", "prod_b", "with_a") + _install("Beta", "prod_b", "with_b"),
     "installed from producer `prod_b`, expected `prod_a`"),
    ("wrong attachment",
     _install("Alpha", "prod_a", "with_b") + _install("Beta", "prod_b", "with_b"),
     "attaches through `with_b`, expected `with_a`"),
    ("wrong seam (swapped valid seams)",
     _install("Beta", "prod_a", "with_a") + _install("Alpha", "prod_b", "with_b"),
     "Seam::Beta is installed from producer `prod_a`, expected `prod_b`"),
    ("a mapped seam declared literally",
     _install("Alpha", "prod_a", "with_a") + "posture.declare(Seam::Beta, b);\n",
     "Seam::Beta is not installed through install_capability"),
]


def selftest() -> int:
    """A gate that cannot fail proves nothing, so prove it fails on each defect."""
    results = []
    with tempfile.TemporaryDirectory() as raw:
        for name, declaring, expected in _SELFTEST_CASES:
            tmp = Path(raw) / name.replace(" ", "_")
            tmp.mkdir()
            results.append(_verdict(name, check(_selftest_tree(tmp, declaring), {}), expected))
    results.append(_selftest_variant_missing_from_all())
    with tempfile.TemporaryDirectory() as raw:
        for name, declaring, expected in _CORRESPONDENCE_CASES:
            tmp = Path(raw) / name.replace(" ", "_")
            tmp.mkdir()
            results.append(_verdict(name, check(_selftest_tree(tmp, declaring), _MAP), expected))
    if not all(results):
        print("seam-posture gate: SELFTEST FAILED")
        return 1
    print("seam-posture gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    failures = check(REPO)
    if failures:
        print("seam-posture gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("seam-posture gate: every Seam states its posture in app.rs or app/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
