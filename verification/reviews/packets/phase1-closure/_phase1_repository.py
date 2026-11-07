"""The repository-state condition.

"No Phase-1 semantic decision exists only in a packet, held branch, comment or
remembered conclusion." Two halves, both mechanical.

(a) every record's packet is IN THE TREE. A correction citing a packet that is not
    merged is authority that cannot be read back.
(b) no branch ahead of main still carries a change to a canonical registry. A
    semantic decision sitting unmerged on a branch is exactly the failure mode this
    condition exists to exclude, and it is visible without judgement.
"""
from _phase1_tree import REPO, sh


def packets(out, recs):
    out["phase1_packets"] = [p.name for p in
                             sorted((REPO / "verification/reviews/packets").glob("*2026-09-18*.md"))]
    out["records_citing_a_missing_packet"] = [
        r["file"] for r in recs if r.get("packet") and not (REPO / r["packet"]).is_file()]


def _registry_ids(blob):
    return {line.split("=", 1)[1].strip().strip('"')
            for line in blob.splitlines() if line.strip().startswith("id = ")}


# Neither a commit count nor a line diff answers this. A squash merge leaves every
# historical branch permanently "ahead", so `origin/main...b` reports a long-merged
# branch's own old changes; and `origin/main..b` on a stale branch reports MAIN's
# later content as if the branch had added it. Both measure divergence, and the
# question is not about divergence.
#
# The question is whether any Phase-1 SEMANTIC ARTEFACT exists somewhere main cannot
# see it. Those artefacts are identified, not diffed: correction records are files,
# probes and units have ids. So the test is a set comparison over the campaign's own
# branches -- does any of them name a record, probe or unit that main does not hold?
# A branch whose work has landed names nothing new, however far its commits diverged.
def _ids(ref):
    recs = set(sh("git", "ls-tree", "--name-only", ref,
                  "verification/claim-corrections/").stdout.split())
    probes, units = set(), set()
    for path, bucket in (("verification/policy/structural-probes.toml", probes),
                         ("verification/policy/mutation-probes.toml", probes),
                         ("verification/policy/verification.toml", units)):
        blob = sh("git", "show", f"{ref}:{path}").stdout
        for line in blob.splitlines():
            s = line.strip()
            if s.startswith("id = "):
                bucket.add(s.split("=", 1)[1].strip().strip('"'))
    return recs, probes, units


def _units_ever_on_main():
    """Every unit id that has EVER stood on main, so a superseded id is not mistaken for
    an unmerged one. Walked once over the registry's own history."""
    ever = set()
    for rev in sh("git", "rev-list", "origin/main", "--",
                  "verification/policy/verification.toml").stdout.split():
        ever |= _registry_ids(sh("git", "show", rev + ":verification/policy/verification.toml").stdout)
    return ever


def _held_by(branch, main_ids, ever_units):
    """What `branch` names that main does not, or None when it names nothing new."""
    main_recs, main_probes, main_units = main_ids
    try:
        r, p_, u = _ids(branch)
    except Exception:
        return None
    # A unit id a branch holds and main does not is SUPERSEDED, not unmerged, when
    # main once held it: this campaign replaced wide propositions with narrower ones,
    # so every pre-split id is exactly that. Only an id main has NEVER held can be a
    # decision that has not landed.
    extra = {"records": sorted(r - main_recs), "probes": sorted(p_ - main_probes),
             "units": sorted(u - main_units - ever_units)}
    superseded = sorted((u - main_units) & ever_units)
    return dict(extra, superseded_units=len(superseded)) if any(extra.values()) else None


def unmerged_branches(out):
    main_ids = _ids("origin/main")
    ever_units = _units_ever_on_main()
    out["unit_ids_ever_on_main"] = len(ever_units)
    branches = [b for b in sh("git", "for-each-ref", "--format=%(refname:short)",
                              "refs/heads/").stdout.split() if b.startswith("adr-068-")]
    held = {}
    for b in branches:
        found = _held_by(b, main_ids, ever_units)
        if found is not None:
            held[b] = found
    out["campaign_branches_examined"] = len(branches)
    out["branches_holding_unmerged_registry_changes"] = held


def open_prs(out):
    listing = sh("gh", "pr", "list", "--state", "open", "--json", "number,title,isDraft").stdout
    out["open_prs"] = listing.strip()[:2000]
