"""A cited control must be compiled by the target that cites it — feature lanes.

`proxy.scrapi_registration_leaf` and `proxy.capsule_anchor_registration_leaf` cited all 33 of
their controls in `//mcp-re-proxy:proxy_unit_test`. That target is built without
`scitt_registration`, the feature both leaves are compiled under, so it held none of them, ran
none of them, and both units read green while measuring nothing. The control census matches a
control by project and path, not by the features of the target that runs it, so it did not see
it (finding d934b11ff4f4b4d6).

The rule this suite holds: for every registry selector `//pkg:target#module::path::test` whose
target is a crate test (an `nt_rust_test` with `crate = ...`, which compiles the library's
sources under ITS OWN `crate_features`), every `#[cfg(feature = "...")]` on a module declaration
between the crate root and the test's module must be satisfied by that target's features.
Selectors are read from units' `tested_symbols` and probes' `expect_red`. Integration-test
targets are out of scope: their selectors name files under `tests/`, not gated library modules.

Each assertion has its control: a gated selector placed in a featureless target is caught, and
the measurement covers a non-empty set of gated selectors, so a parser that found no gate would
not read as a clean registry.

Run: python3 tools/verification/test_feature_lanes.py
"""

from __future__ import annotations

import functools
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _module_tree import declaration_chain  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "verification" / "policy"

_RULE = re.compile(r"^(\w+)\(\s*$", re.M)


def _rules(build: str) -> dict[str, dict]:
    """Each rule in a BUILD file: name -> {kind, crate, features}. Features resolve list
    literals, file-level list constants and their `+` sums."""
    constants = {
        m.group(1): re.findall(r'"([^"]+)"', m.group(2))
        for m in re.finditer(r"^([A-Z_][A-Z0-9_]*) = \[(.*?)^\]", build, re.M | re.S)
    }
    rules: dict[str, dict] = {}
    starts = [(m.start(), m.group(1)) for m in _RULE.finditer(build)]
    for index, (start, kind) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(build)
        body = build[start:end]
        name = re.search(r'^\s*name = "([^"]+)"', body, re.M)
        if not name:
            continue
        crate = re.search(r'^\s*crate = "([^"]+)"', body, re.M)
        features: set[str] = set()
        expr = re.search(r"^\s*crate_features = (.+?),?\s*$", body, re.M)
        if expr:
            for term in expr.group(1).split("+"):
                term = term.strip().rstrip(",")
                if term.startswith("["):
                    features.update(re.findall(r'"([^"]+)"', term))
                elif term in constants:
                    features.update(constants[term])
        rules[name.group(1)] = {"kind": kind, "crate": crate and crate.group(1), "features": features}
    return rules


@functools.cache
def _package_rules(package: str) -> dict[str, dict]:
    build = REPO / package / "BUILD.bazel"
    return _rules(build.read_text(encoding="utf-8")) if build.is_file() else {}


def _requirement(attributes: list[str]) -> list[frozenset[str]]:
    """The feature requirements a declaration's `cfg` attributes state, as alternatives: each
    entry is a set of which at least one must hold. `not(...)` states no requirement, and
    neither does an `any(...)` naming `test`: every target this suite judges is a test build."""
    required = []
    for attr in attributes:
        if not attr.startswith("#[cfg(") or "not(" in attr:
            continue
        named = frozenset(re.findall(r'feature\s*=\s*"([^"]+)"', attr))
        if not named:
            continue
        if "any(" in attr:
            if re.search(r"\btest\b", re.sub(r'"[^"]*"', "", attr)):
                continue
            required.append(named)
        else:
            required.extend(frozenset({feature}) for feature in named)
    return required


@functools.cache
def module_requirement(package: str, module_path: str) -> tuple[frozenset[str], ...]:
    """Every feature requirement on the way from `package/src/lib.rs` to `module_path`.

    The declarations on the way are `_module_tree`'s: inline modules are followed inside
    their file, file modules to the file rustc compiles.
    """
    root = REPO / package / "src" / "lib.rs"
    if not root.is_file():
        return ()
    chain = declaration_chain(root, tuple(module_path.split("::")))
    return tuple(need for decl in chain for need in _requirement(list(decl.attributes)))


def _selectors() -> list[tuple[str, str]]:
    """(owner, selector) for every unit control and every probe's expect_red."""
    verification = tomllib.loads((POLICY / "verification.toml").read_text(encoding="utf-8"))
    probes = tomllib.loads((POLICY / "mutation-probes.toml").read_text(encoding="utf-8"))
    out = [(unit["id"], s) for unit in verification.get("unit", []) for s in unit.get("tested_symbols", [])]
    out += [(probe["id"], s) for probe in probes.get("probe", []) for s in probe.get("expect_red", [])]
    return out


def violation(selector: str) -> str | None:
    """Why `selector`'s target cannot compile the control it names, or None. A selector whose
    target is not a crate test is out of scope (None)."""
    match = re.match(r"^//([^:]+):([^#]+)#(.+)$", selector)
    if not match:
        return None
    package, target, symbol = match.groups()
    rule = _package_rules(package).get(target)
    if not rule or not rule["crate"]:
        return None
    module = symbol.rsplit("::", 1)[0]
    missing = [sorted(need) for need in module_requirement(package, module) if not need & rule["features"]]
    if missing:
        return f"{selector}: //{package}:{target} is built with {sorted(rule['features'])}, the module needs {missing}"
    return None


def _gated(selector: str) -> bool:
    match = re.match(r"^//([^:]+):([^#]+)#(.+)$", selector)
    if not match:
        return False
    package, target, symbol = match.groups()
    rule = _package_rules(package).get(target)
    return bool(rule and rule["crate"] and module_requirement(package, symbol.rsplit("::", 1)[0]))


def test_every_cited_crate_test_control_is_compiled_by_its_target():
    problems = sorted({f"{owner}: {v}" for owner, s in _selectors() if (v := violation(s))})
    assert not problems, "\n".join(problems)


def test_the_measurement_covers_feature_gated_controls():
    """An empty join reads as a clean registry: the gated selectors must be found at all."""
    gated = [s for _, s in _selectors() if _gated(s)]
    assert len(gated) >= 33, f"only {len(gated)} feature-gated selectors found"


def test_control_a_gated_control_cited_in_a_featureless_target_is_caught():
    bad = "//mcp-re-proxy:proxy_unit_test#transparency::auditor::registration::scrapi::tests::every_post_submission_fault_is_indeterminate"
    good = bad.replace(":proxy_unit_test#", ":proxy_auditor_unit_test#")
    caught = violation(bad)
    assert caught is not None and "scitt_registration" in caught, caught
    assert violation(good) is None, violation(good)


def test_control_a_gate_any_test_satisfies_is_no_requirement():
    """`#[cfg(any(test, feature = "pre_052_fixtures"))]` holds in every test build."""
    assert _requirement(['#[cfg(any(test, feature = "pre_052_fixtures"))]']) == []
    assert _requirement(['#[cfg(all(test, feature = "scitt_registration"))]']) == [frozenset({"scitt_registration"})]
    assert _requirement(['#[cfg(not(feature = "x"))]']) == []


def test_the_scitt_evidence_lane_carries_the_feature():
    """The target the registration leaves cite must keep `scitt_registration`."""
    assert "scitt_registration" in _package_rules("mcp-re-proxy")["proxy_auditor_unit_test"]["features"]


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
