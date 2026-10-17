#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render the ADR-MCPRE-051 §7 SLO Job manifest from its literal template.

THE FAILURE CLASS. The Job manifest used to live in an UNQUOTED shell heredoc inside
`tools/slo/run_slo_job.sh`, so every byte of it was subject to parameter expansion and
command substitution. A YAML comment containing backticks was executed as a command ("1:
command not found"). Fixing that one comment would leave the class: the next comment with a
backtick or a `$( )`, or a value carrying one, runs on the operator's machine.

So template and substitution are separated. `tools/slo/slo-job.yaml` is literal text that no
shell ever evaluates; this renderer replaces exactly the `@@FIELD@@` placeholders it knows,
each value checked against that field's own pattern (no quote, newline, `$` or backtick can
pass any of them), and it refuses an unknown field, a missing field and a placeholder left
unresolved. The output is written to stdout for `kubectl apply -f -`.

Run:  python3 tools/slo/render_slo_job.py --template tools/slo/slo-job.yaml JOB=x HW=y ...
      python3 tools/slo/render_slo_job.py --selftest
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

#: field -> the pattern its value must match in full.
FIELDS: dict[str, re.Pattern[str]] = {
    "JOB": re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"),
    "NODE_LABEL": re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9./_-]{0,252}=[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)?"),
    "REDIS_IMG": re.compile(r"[A-Za-z0-9][A-Za-z0-9./:@_-]*"),
    "BENCH_IMG": re.compile(r"[A-Za-z0-9][A-Za-z0-9./:@_-]*"),
    "PULL_POLICY": re.compile(r"Always|IfNotPresent|Never"),
    "HW": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*"),
    "CORES": re.compile(r"[0-9]{1,4}"),
    "WORKERS_PER_SHARD": re.compile(r"[0-9]{1,4}"),
    "CONCURRENCY": re.compile(r"[0-9]{1,6}"),
    "REQUESTS": re.compile(r"[0-9]{1,9}"),
    "CPU_REQUEST": re.compile(r"[0-9]+(?:\.[0-9]+)?m?"),
    "MEM_REQUEST": re.compile(r"[0-9]+(?:Ki|Mi|Gi)?"),
}
PLACEHOLDER = re.compile(r"@@([A-Z_]+)@@")


class RenderError(ValueError):
    pass


def render(template: str, values: dict[str, str]) -> str:
    unknown = sorted(set(values) - set(FIELDS))
    if unknown:
        raise RenderError(f"unknown field(s): {', '.join(unknown)}")
    missing = sorted(set(FIELDS) - set(values))
    if missing:
        raise RenderError(f"missing field(s): {', '.join(missing)}")
    for name, value in values.items():
        if not FIELDS[name].fullmatch(value):
            raise RenderError(f"{name}={value!r} does not match {FIELDS[name].pattern}")
    # NODE_LABEL is the one field rendered into structure rather than spliced as text.
    substitutions = dict(values)
    label = substitutions.pop("NODE_LABEL")
    substitutions["NODE_SELECTOR"] = "{}" if not label else '{ "%s": "%s" }' % tuple(label.split("=", 1))

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in substitutions:
            raise RenderError(f"the template names @@{name}@@, which is not a renderable field")
        return substitutions[name]

    out = PLACEHOLDER.sub(replace, template)
    if PLACEHOLDER.search(out):
        raise RenderError("a placeholder is still unresolved after rendering")
    return out


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    if len(argv) < 2 or argv[0] != "--template":
        print("usage: render_slo_job.py --template <file> FIELD=value ...", file=sys.stderr)
        return 2
    template = Path(argv[1]).read_text(encoding="utf-8")
    values: dict[str, str] = {}
    for pair in argv[2:]:
        name, sep, value = pair.partition("=")
        if not sep:
            print(f"render_slo_job: {pair!r} is not FIELD=value", file=sys.stderr)
            return 2
        values[name] = value
    try:
        sys.stdout.write(render(template, values))
    except RenderError as exc:
        print(f"render_slo_job: REFUSED — {exc}", file=sys.stderr)
        return 1
    return 0


GOOD = {
    "JOB": "slo-kindlocal-1c", "NODE_LABEL": "", "REDIS_IMG": "redis:7-alpine",
    "BENCH_IMG": "mcp-re-slo-bench:0.18.1", "PULL_POLICY": "Never", "HW": "kind-local",
    "CORES": "1", "WORKERS_PER_SHARD": "1", "CONCURRENCY": "128", "REQUESTS": "8000",
    "CPU_REQUEST": "1", "MEM_REQUEST": "512Mi",
}


def _refused(template: str, values: dict[str, str], needle: str) -> None:
    try:
        render(template, values)
    except RenderError as exc:
        assert needle in str(exc), (needle, str(exc))
        return
    raise AssertionError(f"rendered, expected refusal containing {needle!r}")


def selftest() -> int:
    template = (HERE / "slo-job.yaml").read_text(encoding="utf-8")
    out = render(template, GOOD)
    assert "@@" not in out and "nodeSelector: {}" in out and 'value: "kind-local"' in out
    assert "`1 passed`" in out, "a backtick comment in the template must survive verbatim"
    labelled = render(template, dict(GOOD, NODE_LABEL="eks.amazonaws.com/nodegroup=ng-x"))
    assert 'nodeSelector: { "eks.amazonaws.com/nodegroup": "ng-x" }' in labelled

    # Values are data: nothing that could leave its YAML scalar or reach a shell passes.
    for name, bad in (("HW", "x`id`"), ("HW", "x$(id)"), ("JOB", "a\nkind: Pod"),
                      ("BENCH_IMG", 'img" ; touch /tmp/x'), ("CORES", "1 2"),
                      ("NODE_LABEL", 'k=v"}'), ("PULL_POLICY", "Sometimes")):
        _refused(template, dict(GOOD, **{name: bad}), name)
    _refused(template, dict(GOOD, EXTRA="1"), "unknown field")
    _refused(template, {k: v for k, v in GOOD.items() if k != "HW"}, "missing field")
    _refused(template + "\n# @@NOT_A_FIELD@@\n", GOOD, "NOT_A_FIELD")

    # THE CLASS, end to end: a template carrying backticks and a $( ) in a comment, run
    # through the REAL tools/slo/run_slo_job.sh against a recording kubectl stub. Nothing
    # may execute, and the applied manifest must carry the injected text verbatim.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "tools" / "slo").mkdir(parents=True)
        for name in ("run_slo_job.sh", "render_slo_job.py"):
            shutil.copy2(HERE / name, root / "tools" / "slo" / name)
        (root / "VERSION").write_text("0.0.0\n")
        canary = root / "EXECUTED"
        injected = f"# hostile comment: `touch {canary}` and $(touch {canary}) and ${{HOME}}\n"
        (root / "tools" / "slo" / "slo-job.yaml").write_text(injected + template)
        stub = root / "bin"
        stub.mkdir()
        applied = root / "applied.yaml"
        report = '{"results":{"successes":8,"failures":0,"throughput_rps":1.0,' \
                 '"added_latency_us":{"p50":1,"p99":2,"p999":3}}}'
        (stub / "kubectl").write_text(
            "#!/bin/bash\n"
            f'case " $* " in\n'
            f'  *" apply "*) cat > "{applied}" ;;\n'
            '  *" get pods "*) echo pod-1 ;;\n'
            f"  *\" logs \"*) printf '===REPORT_JSON_BEGIN===\\n%s\\n===REPORT_JSON_END===\\n' '{report}' ;;\n"
            "esac\nexit 0\n"
        )
        (stub / "kubectl").chmod(0o755)
        env = dict(os.environ, PATH=f"{stub}:{os.environ['PATH']}", BENCH_IMG="mcp-re-slo-bench:0.0.0",
                   PULL_POLICY="Never", CPU_REQUEST="1", MEM_REQUEST="512Mi")
        result = subprocess.run(
            ["bash", str(root / "tools" / "slo" / "run_slo_job.sh"), "kind-local", "1", str(root / "out.json")],
            env=env, capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert not canary.exists(), "template text was EXECUTED by the shell"
        assert "command not found" not in result.stderr, result.stderr
        assert injected.strip() in applied.read_text(), "the applied manifest lost the literal text"
        assert '"successes":8' in (root / "out.json").read_text()
    print("render_slo_job selftest: OK (template text is never executed; values are pattern-checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
