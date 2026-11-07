# SPDX-License-Identifier: Apache-2.0
"""The campaign case of the selftest: the REAL `ceiling.py campaign` against fake instruments."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from phases import RUNG_REQUEST_CEILING
from selftest_fakes import FAKE_BENCH, FAKE_PROXY, FAKE_RIG, FakePrimary

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Campaign:
    """One selftest campaign: where it runs, how it is launched, and what it is launched with."""

    root: Path
    run_dir: Path
    bins: Path
    base: list[str]
    env: dict
    usable: int
    expect_ok: list[str]


def _install_fake_binaries(bins: Path) -> None:
    bins.mkdir()
    for name in ("saturation_backend", "saturation_loadgen"):
        (bins / name).write_text("#!/bin/sh\nexit 0\n")
    for name in ("mcp-re-proxy-deploy", "mcp-re-proxy-ext"):
        (bins / name).write_text(FAKE_PROXY)
    (bins / "tls_load_harness_bench").write_text(FAKE_BENCH)
    (bins / "saturation_rig").write_text(FAKE_RIG)
    for path in bins.iterdir():
        path.chmod(0o755)


def _campaign(root: Path) -> Campaign:
    bins = root / "bin"
    _install_fake_binaries(bins)
    identity = root / "identity.json"
    identity.write_text(json.dumps({"release_tag": "v0.18.0", "product_commit": "9dab7082",
                                    "tooling_commit": "selftest"}))
    run_dir = root / "run"
    online = os.cpu_count() or 2
    usable = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else online
    # The declared-context check compares online AND usable CPUs; a CI container whose
    # affinity mask is narrower than the machine cannot be "the declared host" at all.
    expect_ok = ["--expect-vcpus", str(usable)] if usable == online else []
    counter = root / "set-calls"
    counter.write_text("0")
    primary = FakePrimary(counter)
    threading.Thread(target=primary.serve_forever, daemon=True).start()
    base = [sys.executable, str(HERE / "ceiling.py"), "campaign", str(run_dir), "--bin-dir", str(bins),
            "--identity", str(identity), "--redis-url", f"redis://127.0.0.1:{primary.server_address[1]}",
            "--cores", "1,2,4", "--reps", "2", "--b-modes", "cold", "--b-repeats", "2", "--partitioned", "",
            "--stage-timers", "--replay-redis-pool-size", "16"]
    env = dict(os.environ, FAKE_FAIL_REP_AT="c2-rep2", FAKE_SET_COUNTER=str(counter),
               FAKE_RUNG_CEILING=str(RUNG_REQUEST_CEILING), FAKE_RIG_COLLAPSE="c2")
    return Campaign(root, run_dir, bins, base, env, usable, expect_ok)


def _refusals(c: Campaign) -> None:
    # A pool the proxy does not admit is refused before anything is created.
    bad = subprocess.run([*c.base[:-1], "129"], env=c.env, capture_output=True, text=True)
    assert bad.returncode == 2 and "between 1 and 128" in bad.stderr and not c.run_dir.exists(), bad.stderr

    # A proxy that states a pool other than the one asked for fails the smoke: no sweep.
    ignored = c.root / "ignored"
    ig = subprocess.run([*c.base[:3], str(ignored), *c.base[4:]], env=dict(c.env, FAKE_PROXY_STATES_POOL="8"),
                        capture_output=True, text=True)
    assert ig.returncode == 4 and not (ignored / "phase-b").exists(), ig.stdout + ig.stderr
    assert json.loads((ignored / "manifest.json").read_text())["replay_pool"]["effective_at_smoke"]["rig"]["replay_pool"] == [8]

    # Binaries that are not the ones the bootstrap built are refused before anything runs.
    build = c.root / "build-identity.json"
    build.write_text(json.dumps({"binaries": {"tls_load_harness_bench": "0" * 64}}))
    drift = subprocess.run(c.base + ["--build-identity", str(build)], env=c.env, capture_output=True, text=True)
    assert drift.returncode == 5 and not (c.run_dir / "phase-a").exists(), drift.stdout + drift.stderr

    # A host that is not the declared context stops BEFORE any measurement.
    wrong = subprocess.run(c.base + ["--expect-vcpus", str(c.usable + 1)], env=c.env, capture_output=True, text=True)
    assert wrong.returncode == 3, wrong.stdout + wrong.stderr
    assert not (c.run_dir / "phase-a").exists(), "measured on an undeclared host"
    assert json.loads((c.run_dir / "host" / "identity-check.json").read_text())["problems"]


def _run_campaign(c: Campaign) -> None:
    # Launched as the `ubuntu` login shell launches it: umask 0002.
    result = subprocess.run(c.base + c.expect_ok, env=c.env, capture_output=True, text=True,
                            preexec_fn=lambda: os.umask(0o002))
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    for rel in ("manifest.json", "summary.json", "summary.md", "SHA256SUMS", "logs/steps.json",
                "logs/campaign.log", "host/inventory-before.json", "host/inventory-after.json",
                "phase-a/scaling/c1/rep1.json", "phase-a/scaling/c1/point.json",
                "phase-a/shipped-auto/c0/point.json", "phase-b/scaling/c4/attempt1/rung2.json",
                "phase-b/shipped-auto/c0/attempt2/point.json", "phase-a/smoke/rig-smoke.log"):
        assert (c.run_dir / rel).is_file(), rel


def _manifest(c: Campaign) -> dict:
    manifest = json.loads((c.run_dir / "manifest.json").read_text())
    assert manifest["binaries"]["bench"]["sha256"].startswith("sha256:") and manifest["finished"]
    assert (manifest["umask"], manifest["umask_inherited"]) == ("0022", "0002"), manifest
    pool = manifest["replay_pool"]
    assert (pool["requested"], pool["expected"]) == (16, 16), pool
    assert {k: v["replay_pool"] for k, v in pool["effective_at_smoke"].items()} == {"phase_a": [16], "rig": [16]}, pool
    assert not manifest["redis"]["managed"] and "primary" in manifest["redis"]["nodes"], manifest["redis"]
    assert manifest["binaries"]["proxy_ext"]["path"].endswith("/mcp-re-proxy-ext"), "the BUILT binary is hashed"
    startup = (c.run_dir / "phase-b" / "scaling" / "c4" / "attempt1" / "rung1.proxy-startup.log").read_text()
    assert "replay redis pool = 16" in startup and "audit:" not in startup, "only the startup transcript is kept"
    return manifest


def _pack(c: Campaign) -> None:
    assert not stale_sums(c.run_dir), f"SHA256SUMS stale after the campaign: {stale_sums(c.run_dir)}"
    # The launcher writes after the campaign; `pack` re-seals before archiving.
    with open(c.run_dir / "logs" / "launcher.txt", "a") as fh:
        fh.write("campaign_rc=0\n")
    packed = subprocess.run([sys.executable, str(HERE / "ceiling.py"), "pack", str(c.run_dir)],
                            capture_output=True, text=True)
    assert packed.returncode == 0, packed.stdout + packed.stderr
    archive = c.root / "run.tar.gz"
    digest, name = (c.root / "run.tar.gz.sha256").read_text().split()
    assert name == "run.tar.gz" and digest == hashlib.sha256(archive.read_bytes()).hexdigest()
    unpacked = c.root / "unpacked"
    with tarfile.open(archive) as tar:
        tar.extractall(unpacked, filter="data")
    assert not stale_sums(unpacked / "run"), f"packed SHA256SUMS stale: {stale_sums(unpacked / 'run')}"


def _point(c: Campaign, *parts: str) -> dict:
    return json.loads(c.run_dir.joinpath(*parts, "point.json").read_text())


def _ladder_points(c: Campaign) -> None:
    c2 = _point(c, "phase-a", "scaling", "c2")
    assert c2["status"] == "INCOMPLETE" and not c2["reps"][1]["valid"], c2["reps"]
    b4 = _point(c, "phase-b", "scaling", "c4", "attempt1")
    assert [r["verdict"] for r in b4["rungs"]] == ["CLIENT", "PROXY"], b4["rungs"]
    assert [r["proxy"]["replay_pool"] for r in b4["rungs"]] == [[16], [16]], b4["rungs"]
    assert b4["redis_queue"]["available"] and b4["redis_queue"]["replica_gap_bytes"][0]["gap_max"] == 60, b4
    assert all(r["store_sets"] == r["expected_sets"] and not r["invalid_reasons"] for r in b4["rungs"]), b4["rungs"]
    assert b4["rungs"][0]["stage_timers"]["available"] is False, "the fake proxy writes no stage timers"


def _collapsed_probe(c: Campaign) -> None:
    # The collapsed probe: INVALID with its reasons, never a PROXY row, never a number.
    b2 = _point(c, "phase-b", "scaling", "c2", "attempt1")
    rung = b2["rungs"][0]
    assert rung["verdict"] == "INVALID" and b2["status"] == "INCOMPLETE", b2
    assert any("generator error" in r for r in rung["invalid_reasons"]), rung["invalid_reasons"]
    assert any("SETs" in r for r in rung["invalid_reasons"]), rung["invalid_reasons"]
    assert len(b2["rungs"]) == 1, "an INVALID rung is not climbed past"
    assert (c.run_dir / "phase-b" / "scaling" / "c4" / "attempt2" / "point.json").is_file(), "no repeat at the high end"


def _recorded_points(c: Campaign) -> None:
    _ladder_points(c)
    _collapsed_probe(c)


def _summary(c: Campaign, manifest: dict) -> None:
    summary = json.loads((c.run_dir / "summary.json").read_text())
    assert summary["rules"]["rig_saturation_pct"] == 5.0
    assert "A/scaling/c2: INCOMPLETE" in summary["inconclusive"], summary["inconclusive"]
    assert set(summary["phase_a"]) == {"scaling", "shipped-auto"}
    assert summary["phase_b"]["scaling"]["rows"][0]["rps_proxy_median"] == 5000.0
    assert summary["phase_b"]["scaling"]["rows"][0]["replay_pool_stated"] == [16]
    c2_row = summary["phase_b"]["scaling"]["rows"][1]
    assert c2_row["cores"] == 2 and set(c2_row["verdicts"]) == {"INVALID"}, c2_row
    assert c2_row["rps_proxy_median"] is None and c2_row["rps_best"] == 0.0, c2_row
    assert c2_row["attribution"]["label"] == "INVALID", c2_row["attribution"]
    assert manifest["plan"]["phase_b"]["signer_retention_budget"] == 800_000, manifest["plan"]
    md = (c.run_dir / "summary.md").read_text()
    assert "Curve 1 — canonical" in md and "Curve 2 — proxy saturation" in md
    assert "replay redis pool: --replay-redis-pool-size 16; expected 16" in md, md


def stale_sums(run_dir: Path) -> list[str]:
    """Files whose SHA256SUMS line does not match, plus files the list omits."""
    listed = {}
    for line in (run_dir / "SHA256SUMS").read_text().splitlines():
        digest, rel = line.split("  ", 1)
        listed[rel] = digest
    bad = [rel for rel, d in listed.items()
           if hashlib.sha256((run_dir / rel).read_bytes()).hexdigest() != d]
    present = {str(p.relative_to(run_dir)) for p in run_dir.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    return sorted(bad + [f"unlisted:{r}" for r in present - set(listed)])


def campaign_case() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        c = _campaign(Path(tmp))
        _refusals(c)
        _run_campaign(c)
        manifest = _manifest(c)
        _pack(c)
        _recorded_points(c)
        _summary(c, manifest)
