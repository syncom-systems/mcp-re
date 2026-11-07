"""finalize.py — close a lane batch: commit what review accepted, revert what it did
not, and record `fixed` for exactly the findings the reviewer accepted. One call.

Per file in the workflow's `results`:

  accept, or partial whose rejections are all `anchor` / `scope`
      the rejected items never landed (an absent anchor or a missing path leaves
      no diff), so the tree holds only accepted work: commit `files_touched`, and
      mark the findings of `items_accepted` `fixed`. The rest stay actionable.
  anything else (reject, a `wrong-fix` / `evidence` / `other` rejection, an
  unordered change, review-failed)
      the diff holds something review did not accept: save it as a patch, return
      the paths to HEAD, record nothing. The file comes back on the next pass.
  gate-failed, no-code-change, dry-run
      nothing to do: `check.py` already reverted a red change, and a file with no
      work has no diff.
  accepted, but a touched file carries an undispositioned control
      a test the change added that no unit claims and no ADR-MCPRE-069 row covers.
      The census is held at its closure state (`scripts/control_census_gate.py`), so
      committing it would move the debt to whoever runs the next gate: revert with the
      patch kept, name the controls, record nothing. The evaluator's next package
      carries the disposition (a registration or a `control-dispositions.toml` row)
      with the change that needs it.

Writers share files and land uncommitted on top of each other, so both actions work on
the writer's OWN diff (`writer_patch.py`, captured by `check.py`): every revert runs
first, by reverse-applying that writer's patch, and each commit then stages exactly
that writer's hunks. A writer with no recorded patch falls back to its paths whole —
reverted to HEAD with new files saved into the patch, or committed whole.

A finding is `fixed` only through this path — the reviewer's acceptance of a
landed diff — never through an evaluator's or worker's own claim.

Usage:
  finalize.py --results <workflow result JSON> --ledger L --work-dir DIR
              [--trailer "Co-Authored-By: ..."]... [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402
import size_debt  # noqa: E402
import writer_patch  # noqa: E402
from _persist import exclusive  # noqa: E402

HARMLESS_REJECTS = {"anchor", "scope"}
NOTHING_TO_DO = {"gate-failed", "no-code-change", "dry-run", "blocked-platform", "agent-failed"}


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True)


def residue_by_carrier() -> dict[str, list[str]]:
    """The census's undispositioned controls, keyed by the file that carries each."""
    root = _git("rev-parse", "--show-toplevel").stdout.strip()
    sys.path.insert(0, os.path.join(root, "tools", "verification"))
    from _census import census  # noqa: PLC0415 — the tool path is set up above

    out: dict[str, list[str]] = {}
    for control in census().residue:
        out.setdefault(control.carrier, []).append(control.identity)
    return out


def undispositioned(paths: list[str], residue: dict[str, list[str]]) -> list[str]:
    """The controls in `paths` that ADR-MCPRE-069 has not yet dispositioned."""
    return sorted(c for p in paths for c in residue.get(p, []))


def _accepted_in_part(row: dict) -> bool:
    """A partial verdict whose every rejection is one that left no diff behind."""
    rejected = row.get("rejected") or []
    return bool(row.get("accepted")) and all(r.get("cause") in HARMLESS_REJECTS for r in rejected)


def decide(row: dict) -> str:
    verdict = row.get("verdict")
    if verdict in NOTHING_TO_DO:
        return "skip"
    if row.get("unordered_changes"):
        return "revert"
    if verdict == "accept":
        return "commit"
    return "commit" if verdict == "partial" and _accepted_in_part(row) else "revert"


def finding_ids(package: dict, work_ids: list[str]) -> list[str]:
    out: list[str] = []
    for item in package.get("work", []):
        if item.get("id") in work_ids:
            out += item.get("finding_ids") or [item["id"]]
    return sorted(set(out))


def _revert(step: "Step", run: "Run") -> str:
    """Return the writer's paths to HEAD, saving what was removed as a patch."""
    file = step.row["file"]
    tag = os.path.basename(file).replace(".", "-")
    patch = os.path.join(run.work_dir, "review-rejected-%s.patch" % tag)
    if not step.paths:
        # Nothing landed. An empty pathspec is NOT "no paths" to git: `ls-files --` and
        # `checkout HEAD --` would then take the whole tree, erasing every other writer's
        # uncommitted change (batch 64: a rejected writer with no edits did exactly that).
        open(patch, "w").close()
        return patch
    own = writer_patch.patch_path(run.store, file)
    if own:
        return _revert_writers_patch(run.store, file, own, patch)
    return _revert_whole_paths(step.paths, patch)


def _revert_writers_patch(store: str, file: str, own: str, patch: str) -> str:
    ok, why = writer_patch.reverse(store, file)
    with open(patch, "w", encoding="utf-8") as fh:
        fh.write(open(own, encoding="utf-8").read())
    if ok:
        return patch
    raise RevertConflict(why)


def _revert_whole_paths(paths: list[str], patch: str) -> str:
    """No recorded patch: the paths go back to HEAD whole, and new files are saved into the
    patch before they are removed."""
    tracked = _git("ls-files", "--", *paths).stdout.split()
    new_files = [f for f in paths if f not in tracked and os.path.isfile(f)]
    with open(patch, "w", encoding="utf-8") as fh:
        fh.write(_git("diff", "HEAD", "--", *tracked).stdout)
        for f in new_files:
            fh.write(_git("diff", "--no-index", "--binary", "/dev/null", f).stdout)
    if tracked:
        _git("checkout", "HEAD", "--", *tracked)
    for f in new_files:
        os.remove(f)
    return patch


class RevertConflict(Exception):
    """A writer's patch no longer reverse-applies: a later writer edited the same lines."""


@dataclass
class Step:
    """One file of the batch: its review row, the report entry being built, the action
    decided for it, and the paths its writer touched."""

    row: dict
    entry: dict
    action: str
    paths: list[str]


@dataclass
class Run:
    """What one finalize call carries to every file: where writer snapshots and the ledger
    live, the trailers to stamp, and the files a conflicting revert holds back."""

    store: str
    work_dir: str
    ledger: str
    trailers: list[str]
    dry_run: bool
    blocked: set[str] = field(default_factory=set)


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="close a lane batch")
    ap.add_argument("--results", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--trailer", action="append", default=[])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--store", default=None,
                    help="the lane's gates store holding writer snapshots (default: <work-dir>/gates)")
    return ap.parse_args()


def _plan(rows: list[dict], residue: dict[str, list[str]]) -> list[Step]:
    steps = []
    for row in rows:
        action = decide(row)
        paths = row.get("files_touched") or []
        entry = {"file": row["file"], "verdict": row.get("verdict"), "action": action}
        if action == "commit" and not paths:
            entry["action"] = action = "skip"
            entry["why"] = "accepted but no files_touched — nothing to commit"
        held = undispositioned(paths, residue) if action == "commit" else []
        if held:
            entry.update(action="revert", why="undispositioned controls (ADR-MCPRE-069)",
                         undispositioned=held)
            action = "revert"
        steps.append(Step(row, entry, action, paths))
    return steps


def _revert_all(steps: list[Step], run: Run) -> None:
    """Newest writer first, so each reverse-applies onto the tree it left."""
    for step in reversed(steps):
        if run.dry_run or step.action != "revert":
            continue
        size_debt.drop(run.work_dir, step.row["file"])
        try:
            step.entry["patch"] = _revert(step, run)
        except RevertConflict as e:
            step.entry.update(action="revert-conflict", error=str(e))
            run.blocked.update(step.paths)


def _commit_message(row: dict, package: dict, fixed: list[str], trailers: list[str]) -> str:
    items = {i.get("id"): i for i in package.get("work", [])}
    lines = ["security: %s — %d finding(s) remediated (lane review: %s)"
             % (row["file"], len(fixed), row.get("verdict")), ""]
    for wid in row.get("accepted") or []:
        change = str(items.get(wid, {}).get("change", "")).split("\n")[0][:160]
        lines.append("- %s: %s" % (wid, change))
    if trailers:
        lines += [""] + trailers
    return "\n".join(lines) + "\n"


def _git_commit(message: str, *paths: str) -> subprocess.CompletedProcess:
    pathspec = ["--", *paths] if paths else []
    return subprocess.run(["git", "commit", "-q", "-F", "-", *pathspec],
                          input=message, capture_output=True, text=True)


def _commit_writer(step: Step, run: Run, message: str) -> subprocess.CompletedProcess:
    """Stage exactly this writer's hunks when its snapshot allows, else its paths whole."""
    index_clean = not _git("diff", "--cached", "--name-only").stdout.strip()
    staged = writer_patch.stage(run.store, step.row["file"])[0] if index_clean else False
    if staged:
        return _git_commit(message)
    _git("reset", "-q")
    _git("add", "--", *step.paths)
    return _git_commit(message, *step.paths)


def _record_fixed(ledger_path: str, fixed: list[str], sha: str) -> None:
    with exclusive(ledger_path):
        by_id = ledger._load(ledger_path)
        for fid in fixed:
            if fid in by_id:
                by_id[fid]["status"] = "fixed"
                by_id[fid]["verified"] = {"method": "review-accepted", "commit": sha}
        ledger._save(ledger_path, by_id)


def _land(step: Step, run: Run) -> dict:
    """Commit one accepted writer and record its findings; returns the report entry."""
    entry, row = step.entry, step.row
    if run.dry_run or step.action != "commit":
        return entry
    if run.blocked.intersection(step.paths):
        entry.update(action="held", why="shares a path with a writer whose revert conflicted")
        return entry
    package = json.load(open(row["package"], encoding="utf-8")) if row.get("package") else {}
    fixed = finding_ids(package, row.get("accepted") or [])
    commit = _commit_writer(step, run, _commit_message(row, package, fixed, run.trailers))
    if commit.returncode != 0:
        entry.update(action="commit-failed", error=(commit.stderr or commit.stdout).strip()[-300:])
        return entry
    sha = _git("rev-parse", "--short", "HEAD").stdout.strip()
    _record_fixed(run.ledger, fixed, sha)
    grew = size_debt.settle(run.work_dir, row["file"], size_debt.Change(sha, fixed))
    entry.update(commit=sha, fixed=fixed, **({"size_debt_rows": grew} if grew else {}))
    return entry


def _commit_ledger(report: list[dict], run: Run) -> None:
    """Every disposition the batch wrote — the evaluators' closures and the `fixed` above —
    in one commit of its own, after the code it describes."""
    tracked = [run.ledger] + ([size_debt.REGISTER] if os.path.exists(size_debt.REGISTER) else [])
    if run.dry_run or not _git("status", "--porcelain", "--", *tracked).stdout.strip():
        return
    message = "ledger: %d file(s) of a lane batch dispositioned\n" % len(report)
    if run.trailers:
        message += "\n" + "\n".join(run.trailers) + "\n"
    _git("add", "--", *tracked)
    _git_commit(message, *tracked)
    report.append({"ledger_commit": _git("rev-parse", "--short", "HEAD").stdout.strip()})


def main() -> int:
    a = _parse_args()
    run = Run(a.store or os.path.join(a.work_dir, "gates"), a.work_dir, a.ledger, a.trailer,
              a.dry_run)
    doc = json.load(open(a.results, encoding="utf-8"))
    rows = doc.get("results", doc) if isinstance(doc, dict) else doc
    # Measured once, over the tree holding every diff the batch landed: a carrier's
    # residue is attributable to the file whose change touched it.
    residue = residue_by_carrier() if any(decide(r) == "commit" for r in rows) else {}
    # Writer order, not report order: a writer's patch is a diff against the tree the
    # writers before it left, so it stages onto the index only after theirs. Writers with
    # no snapshot (committed whole) sort first, in reported order.
    steps = sorted(_plan(rows, residue),
                   key=lambda step: writer_patch.started(run.store, step.row["file"]) or 0)
    _revert_all(steps, run)
    report = [_land(step, run) for step in steps]
    _commit_ledger(report, run)
    print(json.dumps(report, indent=1))
    return 1 if any(r.get("action") == "commit-failed" for r in report) else 0


if __name__ == "__main__":
    sys.exit(main())
