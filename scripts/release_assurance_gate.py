#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release-assurance gate — the canonical command has a caller, and the document has a record.

THE FAILURE CLASS THIS EXISTS FOR, measured on 2026-09-14:
`tools/verification/review --require-root-complete` is the BINDING closure mode named by
#542 as a done criterion, and it had **zero invokers** — zero shell scripts, zero
workflows. Every occurrence in the tree was prose about the flag. It had been run by hand
for v0.16 and v0.17 and its verdict typed into a provenance document.

A tool with no caller is the false-green class this repository has now recorded three
times: `too-many-lines-threshold` parameterising a lint nobody switched on, a documented
SLO-Job rehearsal with no caller, and this. So the repair is not only to write the command
— it is to make its absence fail.

WHAT THIS PROVES, exactly, in two halves:

1. **INVOCATION.** The release workflow calls `tools/verification/release-assurance` in
   COMMAND POSITION. A mention in a comment or a `name:` is not a call, and this gate's own
   docstring names the path — so a mention-based reading would let the gate satisfy its own
   requirement by describing it.

2. **CORRESPONDENCE.** A release provenance document does not get to state the assurance
   verdict on its own authority. Every document under `docs/releases/` is registered here
   with how its assurance claim is backed, and an UNREGISTERED document is refused: a claim
   this gate has not been taught to check is a claim nobody checks.

3. **PROVENANCE.** A `workflow_dispatch` runs the workflow file of the branch it was
   dispatched from, so a writer can dispatch a branch whose copy of the workflow drops the
   reachability guard and uploads a plausible record. What GitHub itself records about a run
   -- its workflow path, its branch, its event -- cannot be edited from a branch. So a
   mechanized record must name its producing run as `release-assurance.yml@refs/heads/main`
   (checked offline, on every CI run), and `--verify-run RECORD` asks GitHub about that run
   and compares the run's own uploaded record with the file before it is committed: the
   run must be this workflow, on `main`, a successful dispatch, and its artifact must be
   byte-identical to the record.

WHAT IT DOES NOT PROVE. That the release workflow was ever RUN, or that it passed. That is
what the record the workflow uploads is for, and reachability is the half that had actually
come loose.

Run:  python3 scripts/release_assurance_gate.py
      python3 scripts/release_assurance_gate.py --selftest
      python3 scripts/release_assurance_gate.py --verify-run docs/releases/<v>-release-assurance.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from workflow_reader import WorkflowSyntaxError, parse

REPO = Path(__file__).resolve().parent.parent

#: The one authority a release procedure may call. Not a family, not a prefix.
CANONICAL = "tools/verification/release-assurance"

#: The workflow that must call it.
WORKFLOW = Path(".github/workflows/release-assurance.yml")

#: The only workflow ref a committed record may have been produced by.
PRODUCER_REF_SUFFIX = f"/{WORKFLOW}@refs/heads/main"

#: Where release provenance documents live.
RELEASES = Path("docs/releases")

#: How each provenance document's assurance claim is backed. The registry may only shrink
#: in the `pre-mechanism` direction: a historical document is a DATED measurement and is not
#: retroactively falsified by a mechanism that did not exist when it was written — but a new
#: one may not join that class, and an unregistered document is refused outright.
#:
#: `mechanized` — the document carries a `release-assurance` marker block whose commit and
#:               verdict must equal the record COMMITTED beside it, at
#:               `docs/releases/<version>-release-assurance.json`. The record is tracked
#:               rather than left as a CI artifact on purpose: a document checked against a
#:               file that expires in 90 days is a document that stops being checked, and
#:               `.verification/` is gitignored, so a gate reading there would pass on every
#:               fresh checkout by finding nothing.
#: `pre-mechanism` — written before the command existed; the reason is recorded and the
#:               document is not checked for correspondence.
BACKING: dict[str, str] = {
    "v0.16.0-provenance.md": "pre-mechanism",
    "v0.17.0-provenance.md": "pre-mechanism",
}

#: The block a `mechanized` document carries, rendered from the record and never typed.
MARKER_BEGIN = "<!-- release-assurance:begin -->"
MARKER_END = "<!-- release-assurance:end -->"

def invoked(text: str, target: str) -> bool:
    """Does this workflow CALL `target`, rather than mention it?

    A call is `target` run by a step: as the program of a command segment, or as the script
    an interpreter runs, after any environment assignments. The workflow reader gives the
    commands of `run:` steps only, without comments: a step's `name:`, an action's `with:`
    input and a comment are VALUES or prose, and naming the path there runs nothing.
    """
    return any(
        invocation.program == target
        for command in parse(text).commands()
        for invocation in command.invocations()
    )


def render(record: dict) -> str:
    """The document's assurance block, DERIVED from the record.

    Deliberately small: commit, tree, verdict, root completeness. A document may explain a
    result at any length it likes; what it may not do is be the authority for what the
    command returned.
    """
    target = record["target"]
    return "\n".join(
        [
            MARKER_BEGIN,
            f"| release assurance | `{record['verdict']}` |",
            f"| commit | `{target['commit']}` |",
            f"| tree | `{target['tree']}` |",
            f"| root completeness | `{record['root_completeness']}` |",
            f"| recorded at | `{record['recorded_at']}` |",
            f"| produced by | run `{record['producer']['run_id']}` |",
            MARKER_END,
        ]
    )


def block_of(text: str) -> str | None:
    """The document's marker block, or None when it carries none."""
    start = text.find(MARKER_BEGIN)
    end = text.find(MARKER_END)
    if start < 0 or end < 0 or end < start:
        return None
    return text[start : end + len(MARKER_END)]


def invocation_problems(read: dict[str, str]) -> list[str]:
    """The release workflow calls the canonical command."""
    text = read.get(str(WORKFLOW))
    if text is None:
        return [
            f"{WORKFLOW} does not exist. The canonical command `{CANONICAL}` would then "
            "have no caller, which is the state this gate exists to make impossible."
        ]
    try:
        called = invoked(text, CANONICAL)
    except WorkflowSyntaxError as exc:
        return [f"{WORKFLOW} cannot be read, so its caller cannot be established: {exc}"]
    if not called:
        return [
            f"{WORKFLOW} does not invoke `{CANONICAL}` in command position. It may name it "
            "in a comment or a step name; a mention is not a caller, and this gate's own "
            "docstring names the same path."
        ]
    return []


def record_name(document: str) -> str:
    """The record that backs `vX.Y.Z-provenance.md`: `vX.Y.Z-release-assurance.json`."""
    return document.replace("-provenance.md", "-release-assurance.json")


def correspondence_problems(documents: dict[str, str], records: dict[str, dict]) -> list[str]:
    """Every provenance document is registered, and a mechanized one matches its record."""
    problems = []
    for name in sorted(documents):
        backing = BACKING.get(name)
        if backing is None:
            problems.append(
                f"{RELEASES / name} is not registered in BACKING. A release provenance "
                "document states an assurance verdict; one this gate has not been taught "
                "to check is a verdict nobody checks. Register it as `mechanized`."
            )
            continue
        if backing == "pre-mechanism":
            continue
        block = block_of(documents[name])
        if block is None:
            problems.append(
                f"{RELEASES / name} is registered `mechanized` but carries no "
                f"`{MARKER_BEGIN}` block, so its assurance line is typed rather than derived."
            )
            continue
        record = records.get(record_name(name))
        if record is None:
            problems.append(
                f"{RELEASES / name} is `mechanized` and {RELEASES / record_name(name)} is "
                "absent, unreadable, or not a schema-2 release-assurance record. A missing "
                "record is a refusal, never a pass."
            )
            continue
        found = producer_problems(record)
        if found:
            problems += [f"{RELEASES / record_name(name)}: {problem}" for problem in found]
            continue
        expected = render(record)
        if block.strip() != expected.strip():
            problems.append(
                f"{RELEASES / name}'s assurance block disagrees with the record.\n"
                f"  document says:\n    " + "\n    ".join(block.strip().splitlines()) + "\n"
                f"  record says:\n    " + "\n    ".join(expected.strip().splitlines())
            )
    return problems


def producer_problems(record: dict) -> list[str]:
    """A committed record names a run of the release workflow on `main`."""
    made = record.get("producer")
    if not isinstance(made, dict) or made.get("source") != "actions":
        return ["it was not produced by a GitHub Actions run, so no run can vouch for it"]
    problems = []
    if not str(made.get("workflow_ref") or "").endswith(PRODUCER_REF_SUFFIX):
        problems.append(
            f"it was produced by {made.get('workflow_ref')!r}, not by a workflow ref ending "
            f"{PRODUCER_REF_SUFFIX!r}: a dispatch from another branch runs that branch's "
            "copy of the workflow"
        )
    if not str(made.get("run_id") or "").isdigit():
        problems.append("it names no producing run id")
    return problems


def run_provenance_problems(run: dict, artifact: bytes | None, committed: bytes) -> list[str]:
    """What GitHub records about the producing run, against the record about to be committed."""
    problems = []
    if run.get("path") != str(WORKFLOW):
        problems.append(f"run is of {run.get('path')!r}, not {WORKFLOW}")
    if run.get("head_branch") != "main":
        problems.append(f"run was dispatched from {run.get('head_branch')!r}, not main")
    if run.get("event") != "workflow_dispatch":
        problems.append(f"run event is {run.get('event')!r}, not workflow_dispatch")
    if run.get("conclusion") != "success":
        problems.append(f"run concluded {run.get('conclusion')!r}, not success")
    if artifact is None:
        problems.append("the run's release-assurance artifact could not be read")
    elif artifact != committed:
        problems.append("the run's uploaded record is not byte-identical to this file")
    return problems


def gh_run(repo: str | None, run_id: str) -> dict:
    where = repo or "{owner}/{repo}"
    proc = subprocess.run(
        ["gh", "api", f"repos/{where}/actions/runs/{run_id}"],
        cwd=REPO, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"release-assurance gate: cannot read run {run_id}: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def gh_artifact(repo: str | None, run_id: str, name: str) -> bytes | None:
    with tempfile.TemporaryDirectory() as scratch:
        argv = ["gh", "run", "download", run_id, "--name", name, "--dir", scratch]
        if repo:
            argv += ["--repo", repo]
        if subprocess.run(argv, cwd=REPO, capture_output=True, check=False).returncode != 0:
            return None
        path = Path(scratch) / "release-assurance.json"
        return path.read_bytes() if path.is_file() else None


def verify_run(path: Path, repo: str | None, fetch_run=gh_run, fetch_artifact=gh_artifact) -> int:
    """Before a record is committed: GitHub's account of its producing run vouches for it."""
    committed = path.read_bytes()
    record = load_record_obj(json.loads(committed))
    if record is None:
        print(f"release-assurance gate: FAIL — {path} is not a schema-2 release-assurance record")
        return 1
    problems = producer_problems(record)
    if not problems:
        run_id = record["producer"]["run_id"]
        name = f"release-assurance-{record['target']['commit']}-{run_id}"
        problems = run_provenance_problems(
            fetch_run(repo, run_id), fetch_artifact(repo, run_id, name), committed
        )
    for problem in problems:
        print(f"  - {problem}")
    verdict = "FAIL" if problems else "OK"
    print(f"release-assurance gate: {verdict} — provenance of {path.name}")
    return 1 if problems else 0


def load_record_obj(record: object) -> dict | None:
    """A parsed object, if it is a release-assurance record this gate can read."""
    if not isinstance(record, dict) or record.get("kind") != "release-assurance":
        return None
    if record.get("schema_version") != 2:
        return None
    return record


def load_record(path: Path) -> dict | None:
    """The record, or None — where None is 'absent, unreadable or unknown', all refusals."""
    if not path.is_file():
        return None
    try:
        return load_record_obj(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return None


def selftest() -> int:
    """The mutation probe. Each control is shown to FAIL on the thing it forbids."""
    def workflow(steps: str) -> str:
        return "jobs:\n  release-assurance:\n    steps:\n" + steps

    good = workflow("      - run: python3 tools/verification/release-assurance\n")
    assert not invocation_problems({str(WORKFLOW): good})
    assert invocation_problems({}), "an absent workflow must fail"
    assert invocation_problems(
        {str(WORKFLOW): workflow("      # runs tools/verification/release-assurance\n      - run: true\n")}
    ), "a comment naming the command is not a caller"
    assert invocation_problems(
        {str(WORKFLOW): workflow("      - name: tools/verification/release-assurance\n        run: true\n")}
    ), "a step NAME is not a caller"
    assert invocation_problems(
        {str(WORKFLOW): workflow('      - run: echo "next: tools/verification/release-assurance"\n')}
    ), "a usage line is not a caller"
    assert not invocation_problems(
        {str(WORKFLOW): workflow("      - run: FOO=1 python3 ./tools/verification/release-assurance --out x\n")}
    ), "assignments and an interpreter may precede the command"
    assert not invocation_problems(
        {str(WORKFLOW): workflow("      - run: |\n          python3 tools/verification/release-assurance \\\n            --target x\n")}
    ), "a continued command is one call"
    assert invocation_problems({str(WORKFLOW): "x: &anchor 1\n"}), "an unreadable workflow must fail"

    record = {
        "kind": "release-assurance",
        "schema_version": 2,
        "verdict": "PASS",
        "root_completeness": "PASS",
        "recorded_at": "2026-01-01T00:00:00Z",
        "target": {"repository": "r", "commit": "c" * 40, "tree": "t" * 40},
        "producer": {
            "source": "actions",
            "workflow_ref": f"o/r{PRODUCER_REF_SUFFIX}",
            "run_id": "42",
            "run_attempt": "1",
        },
    }
    records = {"v9.9.9-release-assurance.json": record}
    assert not correspondence_problems({"v0.16.0-provenance.md": "anything"}, records)
    assert correspondence_problems({"v9.9.9-provenance.md": "x"}, records), "unregistered refuses"

    BACKING["v9.9.9-provenance.md"] = "mechanized"
    try:
        assert correspondence_problems({"v9.9.9-provenance.md": "no block"}, records)
        matching = "intro\n" + render(record) + "\noutro"
        assert not correspondence_problems({"v9.9.9-provenance.md": matching}, records)
        assert correspondence_problems({"v9.9.9-provenance.md": matching}, {}), (
            "a missing record must refuse a mechanized document, never pass it"
        )
        lying = matching.replace("`PASS`", "`FAIL`", 1)
        assert correspondence_problems({"v9.9.9-provenance.md": lying}, records), (
            "a document claiming a verdict the record does not carry must fail"
        )
        wrong_sha = matching.replace("c" * 40, "d" * 40)
        assert correspondence_problems({"v9.9.9-provenance.md": wrong_sha}, records), (
            "a document naming a different target than the record must fail"
        )
        branch = dict(record, producer=dict(record["producer"], workflow_ref=f"o/r/{WORKFLOW}@refs/heads/x"))
        assert correspondence_problems(
            {"v9.9.9-provenance.md": matching}, {"v9.9.9-release-assurance.json": branch}
        ), "a record produced by another branch's copy of the workflow must fail"
        local = dict(record, producer={"source": "local", "workflow_ref": None, "run_id": None})
        assert correspondence_problems(
            {"v9.9.9-provenance.md": matching}, {"v9.9.9-release-assurance.json": local}
        ), "a record no Actions run produced must fail"
        malformed = dict(record, schema_version=99)
        assert load_record_obj(malformed) is None, (
            "an unknown schema version is refused rather than read optimistically"
        )
    finally:
        del BACKING["v9.9.9-provenance.md"]

    assert load_record(Path("/nonexistent/x.json")) is None

    good_run = {"path": str(WORKFLOW), "head_branch": "main", "event": "workflow_dispatch", "conclusion": "success"}
    assert run_provenance_problems(good_run, b"x", b"x") == []
    for field, value in (("path", ".github/workflows/other.yml"), ("head_branch", "x"),
                         ("event", "push"), ("conclusion", "failure")):
        assert run_provenance_problems(dict(good_run, **{field: value}), b"x", b"x"), (
            f"a run whose {field} is {value!r} must not vouch for a record"
        )
    assert run_provenance_problems(good_run, b"y", b"x"), "a different uploaded record must fail"
    assert run_provenance_problems(good_run, None, b"x"), "an unreadable artifact must fail"

    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "v9.9.9-release-assurance.json"
        body = json.dumps(record).encode()
        path.write_bytes(body)
        asked = []
        def fetch_artifact(repo, run_id, name):
            asked.append(name)
            return body
        assert verify_run(path, None, lambda repo, run_id: good_run, fetch_artifact) == 0
        assert asked == [f"release-assurance-{'c' * 40}-42"], asked
        assert verify_run(path, None, lambda repo, run_id: dict(good_run, head_branch="x"), fetch_artifact) == 1
    print("release-assurance gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    if "--verify-run" in sys.argv[1:]:
        args = sys.argv[1:]
        index = args.index("--verify-run")
        if index + 1 >= len(args):
            raise SystemExit("--verify-run needs the record file")
        repo = args[args.index("--repo") + 1] if "--repo" in args else None
        return verify_run(Path(args[index + 1]), repo)
    read = {}
    if (REPO / WORKFLOW).is_file():
        read[str(WORKFLOW)] = (REPO / WORKFLOW).read_text(encoding="utf-8")
    documents = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((REPO / RELEASES).glob("*-provenance.md"))
    }
    records = {}
    for path in sorted((REPO / RELEASES).glob("*-release-assurance.json")):
        loaded = load_record(path)
        if loaded is not None:
            records[path.name] = loaded
    problems = invocation_problems(read) + correspondence_problems(documents, records)
    if problems:
        print("release-assurance gate: FAIL", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    mechanized = sum(1 for name in documents if BACKING.get(name) == "mechanized")
    print(
        f"release-assurance gate: OK — {WORKFLOW.name} invokes `{CANONICAL}`; "
        f"{len(documents)} provenance document(s), {mechanized} mechanized, "
        f"{len(documents) - mechanized} pre-mechanism and recorded as such."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
