# SPDX-License-Identifier: Apache-2.0
"""Text checks that couple what the chart documents to the Rust constants it describes."""

from __future__ import annotations

import re
from pathlib import Path

from _helm_render.config import REPO, chart_text, prose

IN_FLIGHT_OWNER = "mcp-re-proxy/src/config_state/in_flight_limit.rs"
FLUSH_OWNER = "mcp-re-proxy/src/audit_sink/drain.rs"
AUDIT_FLAGS = "mcp-re-proxy/src/cli/audit_flags.rs"


def _source(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _value_after(source: str, prefix: str, tail: str) -> str:
    """The text between `prefix` and the next `tail`, on the first line that starts with `prefix`."""
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split(prefix, 1)[1].split(tail, 1)[0].strip()
    return ""


def _in_flight_problems(name: str, text: str, actual: str) -> list[str]:
    problems = []
    if "per-core ceiling" not in text:
        problems.append(f"{name} no longer explains the absent-flag ceiling at all")
    elif f"ceiling of {actual}" not in text:
        problems.append(f"{name} does not state the code's per-core ceiling of {actual}")
    if "UNBOUNDED" in text or "unbounded ceiling" in text:
        problems.append(f"{name} still calls the absent-flag default unbounded; "
                        f"the proxy applies {actual}")
    return problems


def check_documented_in_flight_default(root: Path = REPO) -> list[str]:
    """The absent-flag in-flight ceiling the chart DOCUMENTS must be the code's.

    This number is what an operator sizes the boundary against, and the chart is
    where they read it. It had been stated three ways at once — `64` in values.yaml,
    "unbounded" in deployment.yaml, `256` in `ServerLimits::default()` — so two of
    the three files an operator consults were wrong about the control they configure,
    and the "unbounded" wording invited setting a ceiling to escape a fail-open
    default that does not exist. Nothing coupled the prose to the constant, so all
    three could be individually plausible.

    Read from `DEFAULT_PER_CORE_IN_FLIGHT`, the single constant both the validation
    boundary and `ServerLimits::default()` use, so the chart is checked against the
    value the proxy actually applies rather than against one of its two readers.
    """
    # The number lives in ONE place — the constant layer A resolves an unstated limit
    # to, which `ServerLimits::default()` also reads. Following the constant rather
    # than a literal in `ServerLimits` is what keeps this coupled to the value both
    # paths actually use.
    actual = _value_after(
        _source(root, IN_FLIGHT_OWNER), "pub const DEFAULT_PER_CORE_IN_FLIGHT: usize = ", ";"
    )
    if not actual:
        return [f"{IN_FLIGHT_OWNER} declares no "
                "`DEFAULT_PER_CORE_IN_FLIGHT`; the documented default can no longer be "
                "checked against the code"]
    problems: list[str] = []
    # `_helpers.tpl` is the third place the number reaches an operator, and the only
    # one they hit while the render is refusing them.
    for name in ("values.yaml", "templates/deployment.yaml", "templates/_helpers.tpl"):
        problems += _in_flight_problems(name, prose(chart_text(root, name)), actual)
    return problems


def _u32_consts(source: str) -> dict[str, str]:
    """Every `pub const NAME: u32 = value;` in `source`, with digit separators removed."""
    consts = {}
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("pub const ") and ": u32 = " in stripped:
            name, value = stripped[len("pub const "):].split(": u32 = ", 1)
            consts[name] = value.rstrip(";").replace("_", "")
    return consts


def _missing_phrases(text: str, phrases: tuple[str, ...]) -> list[str]:
    return [f"values.yaml does not state the code's {phrase!r}" for phrase in phrases
            if phrase not in text]


def check_documented_handshake_signing_bounds(root: Path = REPO) -> list[str]:
    """The defaults and bounds `values.yaml` states for the handshake-signing capacity
    are `HandshakeSignCapacity`'s.

    The chart renders no default and validates no range — the proxy owns both — so the
    numbers in its comment are prose an operator sizes against, and nothing else couples
    them to the type that enforces them.
    """
    owner = "mcp-re-proxy/src/delegated_tls/sign_capacity.rs"
    consts = _u32_consts(_source(root, owner))
    wanted = ("DEFAULT_RATE_PER_SEC", "DEFAULT_BURST", "MAX_RATE_PER_SEC", "MAX_BURST")
    missing = [n for n in wanted if n not in consts]
    if missing:
        return [f"{owner} declares no {', '.join(missing)}; the chart's "
                "documented capacity can no longer be checked against the code"]
    return _missing_phrases(
        prose(chart_text(root, "values.yaml")),
        (f"({consts['DEFAULT_RATE_PER_SEC']}/s, burst {consts['DEFAULT_BURST']})",
         f"rate 1..={consts['MAX_RATE_PER_SEC']}",
         f"burst 1..={consts['MAX_BURST']}"),
    )


def check_documented_continuation_bound(root: Path = REPO) -> list[str]:
    """The default and range `values.yaml` states for `continuationControl.maxLiveEntries`
    are `ContinuationCapacity`'s, for the same reason as the handshake-signing capacity."""
    owner = "mcp-re-proxy/src/continuation_store/capacity.rs"
    code = _source(root, owner)
    default = re.search(r"max_live_entries: ([0-9_]+),", code)
    ceiling = re.search(r"pub const MAX_LIVE_ENTRIES: u32 = ([0-9_]+);", code)
    if not default or not ceiling:
        return [f"{owner} declares no default or ceiling; the chart's "
                "documented continuation bound can no longer be checked against the code"]
    return _missing_phrases(
        prose(chart_text(root, "values.yaml")),
        (f"default ({default.group(1).replace('_', '')})",
         f"range (1..={ceiling.group(1).replace('_', '')})"),
    )


def check_audit_flush_budget(root: Path = REPO) -> list[str]:
    """The seconds the chart budgets for the post-serve audit flush must be the code's.

    Serving ending is not the process exiting. `audit_sink::drain::at_shutdown` then waits
    up to `AUDIT_FLUSH_TIMEOUT` for the detached writer to hand over what it already holds,
    and that wait is inside the kubelet's grace period like everything else after pod
    deletion. A chart budgeting only `pre + proxyDrain` describes a shutdown shorter than
    the one that happens — so the drain invariant it enforces is unsound, and the request
    it exists to protect can still be SIGKILLed at the end of a drain the chart called
    legal. It cost nothing to notice, because a template literal agrees with a Rust
    constant only by coincidence until something checks.

    The chart cannot read the constant, so this is the coupling. It is not an operator
    knob: the value bounds an obligation the proxy owns, not a policy the deployment
    chooses, which is why it is a literal in `_helpers.tpl` and not a key in values.yaml.
    """
    actual = _value_after(
        _source(root, FLUSH_OWNER),
        "const AUDIT_FLUSH_TIMEOUT: Duration = Duration::from_secs(",
        ")",
    )
    if not actual:
        return [f"{FLUSH_OWNER} declares no `AUDIT_FLUSH_TIMEOUT`; "
                "the chart's drain arithmetic can no longer be checked against the code"]
    problems = []
    if f"$auditFlush := {actual}" not in chart_text(root, "templates/_helpers.tpl"):
        problems.append(
            f"_helpers.tpl does not budget the proxy's {actual}s audit flush "
            f"($auditFlush := {actual}); the drain invariant is short by that much"
        )
    if f"+ {actual} < drainGracePeriodSeconds" not in prose(chart_text(root, "values.yaml")):
        problems.append(
            f"values.yaml states the drain invariant without the {actual}s audit flush; "
            f"an operator sizing the grace period from it budgets too little"
        )
    return problems


def _parsed_delivery_kinds(flags: str) -> set[str]:
    """The values `delivery_kind` accepts, read from the match arms before its fallback."""
    body = flags.split("fn delivery_kind(", 1)[1]
    return set(re.findall(r'"([a-z-]+)" =>', body.split("other =>", 1)[0]))


def check_audit_commitment_enumeration(root: Path = REPO) -> list[str]:
    """The chart's `auditCommitment` values are exactly the ones the proxy parses.

    `_helpers.tpl` refuses a value outside its list so that a typo names the value instead
    of CrashLooping the pods. That only holds while the list is the parser's: a value the
    parser gained and the chart did not would be refused by the chart for no reason, and one
    the parser lost would render and then fail at startup.
    """
    flags = _source(root, AUDIT_FLAGS)
    if '"--audit-commitment" => self.delivery = Some(delivery_kind(value)?)' not in flags:
        return [f"{AUDIT_FLAGS} does not parse `--audit-commitment` "
                "through `delivery_kind`; the chart's enumeration can no longer be checked "
                "against the parser"]
    if "fn delivery_kind(" not in flags:
        return [f"{AUDIT_FLAGS} has no `delivery_kind`; the chart's "
                "enumeration can no longer be checked against the parser"]
    parsed = _parsed_delivery_kinds(flags)
    listed = re.search(r"has \.Values\.auditCommitment \(list ([^)]*)\)",
                       chart_text(root, "templates/_helpers.tpl"))
    charted = set(re.findall(r'"([^"]+)"', listed.group(1))) if listed else set()
    if parsed != charted:
        return [f"_helpers.tpl allows auditCommitment {sorted(charted)} but the proxy parses "
                f"{sorted(parsed)}"]
    return []
