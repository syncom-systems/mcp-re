# SPDX-License-Identifier: Apache-2.0
"""The unit cases of the selftest: each pins one decision the experiment's analysis rests on."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from analysis import PointSetting, ceiling_statement, classify, describe_curve
from hostfacts import check_expected
from phases import (RUNG_REQUEST_CEILING, rig_steps, rig_verdict, rung_requests, startup_facts,
                    validate_bench_rep)
from redis_queue import replication, store_clients, summarize as queue_summary
from selftest_fakes import telemetry_reading
from stage_sampler import parse as parse_stage_timers, window_means
from telemetry import active_cpu
import isolation

#: The configuration most attribution cases share: four shards of one worker on a 32-vCPU host.
SHARDED = PointSetting(cores=4, workers=1, vcpus=32, verdict=None,
                       client_categories=("loadgen", "rig"), backend_budget=6)


def label(telemetry: dict, verdict: str | None) -> str:
    """The attribution the rules reach for `telemetry` when the instrument's verdict is `verdict`."""
    setting = PointSetting(cores=SHARDED.cores, workers=SHARDED.workers, vcpus=SHARDED.vcpus,
                           verdict=verdict, client_categories=SHARDED.client_categories,
                           backend_budget=SHARDED.backend_budget)
    return classify(telemetry, setting)["label"]


def curves() -> None:
    """Curves: linear has no knee; a bend is found where incremental efficiency < 0.5."""
    linear = describe_curve([(1, 100.0), (2, 200.0), (4, 400.0), (8, 800.0)])
    assert linear["knee"] is None and linear["still_scaling_at_top"] and abs(linear["rows"][-1]["efficiency_vs_1"] - 1) < 1e-9
    bent = describe_curve([(1, 100.0), (2, 190.0), (4, 300.0), (8, 310.0), (16, 312.0)])
    assert bent["knee"] == 8 and bent["plateau_from"] == 4 and not bent["still_scaling_at_top"], bent


def attribution() -> None:
    """Attribution: each rule fires on the evidence it names, in the declared order."""
    assert label(telemetry_reading(), "PROXY") == "PROXY_CPU"
    assert label(telemetry_reading(steal_avg=0.08), "PROXY") == "HOST_SCHEDULING"
    assert label(telemetry_reading(cat_redis__pid_max_cores_avg=0.95), "PROXY") == "REPLAY_TIER"
    assert label(telemetry_reading(cat_backend__cores_avg=5.5), "PROXY") == "BACKEND"
    assert label(telemetry_reading(tcp_tw_max=90000), "PROXY") == "PROXY_CPU", "a TIME_WAIT count is not refusal"
    assert label(telemetry_reading(netstat_delta={"ListenOverflows": 12}), "PROXY") == "OS_CONNECTION_PATH"
    hot1 = telemetry_reading(cat_proxy__cores_avg=2.0, proxy_thread_max_avg=0.99, proxy_threads_hot_avg=1.0)
    assert label(hot1, "PROXY") == "PROXY_SERIALIZATION_OR_CONTENTION"
    hot4 = telemetry_reading(cat_proxy__cores_avg=3.2, proxy_thread_max_avg=0.99, proxy_threads_hot_avg=3.6)
    assert label(hot4, "PROXY") == "PROXY_CPU", "every serving thread saturated"
    assert label(telemetry_reading(), "CLIENT") == "CLIENT_LIMITED"
    assert label(telemetry_reading(host_busy_avg=0.97), "CLIENT") == "INDETERMINATE"
    assert label(telemetry_reading(), "INVALID") == "INVALID"
    low = telemetry_reading(cat_proxy__cores_avg=1.5)
    assert label(low, "PROXY") == "PROXY_SERIALIZATION_OR_CONTENTION"
    assert label(telemetry_reading(cat_proxy__cores_avg=2.0, host_busy_avg=0.95), "PROXY") == "INDETERMINATE"
    assert label(telemetry_reading(cat_proxy__cores_avg=2.8), "PROXY") == "UNEXPLAINED"
    assert label({"available": False}, "PROXY") == "UNATTRIBUTED"
    # shipped auto topology (cores=0): the proxy's budget is the whole host
    auto = PointSetting(cores=0, workers=0, vcpus=32, verdict="PROXY",
                        client_categories=("loadgen",), backend_budget=6)
    assert classify(telemetry_reading(cat_proxy__cores_avg=28.0), auto)["label"] == "PROXY_CPU"


def rep_validation_and_rig_verdicts() -> None:
    """Rep validation and rig verdicts."""
    with tempfile.TemporaryDirectory() as tmp:
        rpt = Path(tmp) / "r.json"
        assert validate_bench_rep(0, "test result: ok. 1 passed", rpt, 8000)[1] == "no report written"
        rpt.write_text(json.dumps({"results": {"successes": 7999, "failures": 0}}))
        assert "7999 of 8000" in validate_bench_rep(0, "test result: ok. 1 passed", rpt, 8000)[1]
        assert "nothing was measured" in validate_bench_rep(0, "running 0 tests", rpt, 8000)[1]
        assert validate_bench_rep(101, "", rpt, 8000)[1] == "bench exited 101"
    # A rung is evidence only if every step of it was served (the 2026-10-16 pool run: every
    # probe at 3 generators hit the signer retention budget, the store counted 800,000 of the
    # 1,600,000 SETs the steps sent, and the rig stamped the collapse PROXY).
    collapsed = {"generators": 2, "last_gain_pct": -94.0, "saturated": True, "failures": 0, "failure_pct": 0.0}
    assert rig_steps(collapsed, 12) == [2, 3]
    assert rig_steps({"generators": 3, "last_gain_pct": 2.0}, 12) == [2, 3], "a probe that won is the row"
    assert rig_steps({"generators": 5, "last_gain_pct": 9.0}, 5) == [2, 3, 4, 5], "CLIENT at the cap: no probe"
    errors = '  generator error: ... {"wire_code":"mcp-re.replay_cache_unavailable"}\n' * 3
    verdict, why = rig_verdict(collapsed, errors, 800_000, 1_600_000)
    assert verdict == "INVALID" and "3 generator error(s)" in why[0] and "replay_cache_unavailable" in why[0], why
    assert "800000 SETs" in why[1], why
    assert rig_verdict(collapsed, "", 799_999, 800_000)[0] == "INVALID", "a short store tally alone refuses the row"
    assert rig_verdict(collapsed, "", None, 800_000)[0] == "INVALID", "an unreadable tally is not a pass"
    assert rig_verdict(dict(collapsed, failures=1), "", 800_000, 800_000)[0] == "INVALID", "any failure"
    assert rig_verdict(collapsed, "", 800_000, 800_000) == ("PROXY", [])
    assert rig_verdict(dict(collapsed, saturated=False), "", 5, 5) == ("CLIENT", [])
    # The cap: a rung climbing to the generator cap never reaches the budget.
    assert rung_requests(256, 200, 5) == (51_200, False)
    capped, was = rung_requests(512, 200, 5)
    assert was and capped * sum(range(2, 6)) <= RUNG_REQUEST_CEILING < 800_000, capped
    assert rung_requests(256, 1250, 12)[1], "the 2026-10-16 main-matrix setting is capped"


def isolation_plan() -> None:
    """Isolation: physical cores come from sysfs siblings, never from logical numbering."""
    assert isolation.parse_cpulist("0-3,8,10-11\n") == [0, 1, 2, 3, 8, 10, 11]
    with tempfile.TemporaryDirectory() as tmp:
        sysfs = Path(tmp)
        (sysfs / "online").write_text("0-31\n")
        for cpu in range(32):                      # the AWS shape: SMT siblings are i and i+16
            (sysfs / f"cpu{cpu}" / "topology").mkdir(parents=True)
            (sysfs / f"cpu{cpu}" / "topology" / "thread_siblings_list").write_text(f"{cpu % 16},{cpu % 16 + 16}\n")
        cores = isolation.topology(sysfs)
        assert len(cores) == 16 and cores[0] == [0, 16] and cores[-1] == [15, 31], cores
        p = isolation.plan(cores)
        assert (p["redis_primary"], p["control"], p["idle_siblings"]) == ([14], [15], [30, 31]), p
        assert p["reserved"] == [14, 15, 30, 31] and len(p["general"]) == 28 and 30 not in p["general"], p
    assert isolation.target("mcp-re-control", list(range(32)), p) == [15]
    assert isolation.target("mcp-re-serve-3", [3], p) == [3], "a shard pinned to a general CPU keeps its pin"
    assert isolation.target("mcp-re-serve-14", [14], p) == p["general"], "a shard on a reserved CPU is moved off"
    assert isolation.target("mcp-re-serve-30", [30], p) == p["general"], "an idle sibling stays idle"
    assert isolation.target("mcp-re-audit", list(range(32)), p) == p["general"]
    try:
        isolation.plan([[0, 4], [1, 5], [2, 6]])
    except ValueError as exc:
        assert "too few" in str(exc)
    else:
        raise AssertionError("a plan on three physical cores")


def active_cpu_needs_activity() -> None:
    """Where a thread ran counts only if it ran: an idle thread's `processor` is stale."""
    # 2026-10-16 isolation run reported the pinned Redis primary "off its CPU" from bio threads
    # that had slept since before the pin).
    assert active_cpu(("redis:primary", 100, 0, 5), ("redis:primary", 100, 0, 5)) is None, "slept: stale"
    assert active_cpu(("redis:primary", 100, 0, 5), ("redis:primary", 900, 0, 14)) == 14
    assert active_cpu(None, ("redis:primary", 900, 0, 14)) is None, "first sight: no interval yet"
    assert active_cpu(("proxy:serve", 100, 0, 3), ("proxy:control", 900, 0, 15)) is None, "a reused tid"


def stage_timers_and_replication() -> None:
    """The proxy's stage timers: cumulative snapshots, differenced to one window."""
    snap = ("stage,count,total_ms,mean_us\nreplay_wait,{n},{ms},0\nscheduler_latency,{s},{sms},0\n"
            "replay_inflight,{n},64,{m}\n")
    s0 = parse_stage_timers(snap.format(n=1000, ms=500.0, s=10, sms=1.0, m=20.0))
    s1 = parse_stage_timers(snap.format(n=3000, ms=2100.0, s=30, sms=5.0, m=30.0))
    assert s0 and s1 and parse_stage_timers("stage,count,total_ms,mean_us\nreplay_wait,1") is None
    w = window_means([{"t": 1.0, "file": "r1", "stages": s0}, {"t": 2.0, "file": "r1", "stages": s1}], 0.0, 3.0)
    assert (w["replay_wait"], w["replay_wait_count"], w["scheduler_latency"], w["replay_inflight_mean"]) == \
        (800.0, 2000, 200.0, 35.0), w
    assert not window_means([{"t": 1.0, "file": "r1", "stages": s0}, {"t": 2.0, "file": "r2", "stages": s1}],
                            0.0, 3.0)["available"], "two proxies' counters are never differenced"
    repl = replication({"master_repl_offset": "1000", "slave0": "ip=127.0.0.1,port=8631,state=online,offset=940,lag=0",
                        "slave1": "ip=127.0.0.1,port=8632,state=online,offset=1000,lag=1"})
    assert [r["gap_bytes"] for r in repl["replicas"]] == [60, 0] and repl["replicas"][1]["ack_age_s"] == 1, repl


def ceiling_statements() -> None:
    """The ceiling statement, all three outcomes."""
    def rows(rps: list[float], label: str = "PROXY_CPU") -> dict:
        ns = [1, 2, 4, 8, 16, 24, 32][:len(rps)]
        rs = [{"cores": n, "rps_proxy_median": t, "stable": True,
               "attribution": {"label": label, "confidence": "high", "why": "x"}} for n, t in zip(ns, rps)]
        return {"rows": rs, "curve": describe_curve(list(zip(ns, rps)))}
    assert ceiling_statement(rows([1, 2, 4, 8, 16, 24, 32]))["statement"] == "PROXY CEILING: NOT REACHED ON THIS HOST"
    reached = ceiling_statement(rows([1, 2, 4, 8, 12, 12.2, 12.1]))
    assert reached["statement"].startswith("PROXY CEILING: REACHED") and reached["plateau_from_cores"] == 16, reached
    assert ceiling_statement(rows([1, 2, 4, 8, 16, 24, 32], "INDETERMINATE"))["statement"] == "CEILING ATTRIBUTION: INDETERMINATE"
    assert ceiling_statement(None)["statement"] == "CEILING ATTRIBUTION: INDETERMINATE"


def replay_store_queueing() -> None:
    """The replay store's connections as the primary lists them, and their queueing."""
    listing = ("id=1 addr=x flags=N cmd=client|list qbuf=0\nid=2 addr=x flags=b cmd=wait qbuf=900\n"
               "id=3 addr=x flags=N cmd=set qbuf=100\nid=4 addr=x flags=S cmd=replconf qbuf=0\nid=5 flags=b cmd=wait qbuf=7")
    assert store_clients(listing, {"5"}) == [{"flags": "b", "qbuf": 900}, {"flags": "N", "qbuf": 100}]
    q = queue_summary([{"t": 0.0, "store_conns": 2, "store_blocked": 1, "qbuf": [900, 100], "set_calls": 0, "wait_calls": 0},
                       {"t": 2.0, "store_conns": 2, "store_blocked": 2, "qbuf": [300, 100], "set_calls": 400, "wait_calls": 398}])
    assert (q["store_conns_max"], q["blocked_in_wait_mean"], q["qbuf_per_conn_mean_bytes"], q["set_per_s"]) == (2, 1.5, 350, 200), q
    assert not queue_summary([])["available"]
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "startup.log"
        log.write_text("mcp-re-proxy: replay-store backend=redis tier=REDIS_WAIT_QUORUM guarantee=x\n"
                       "mcp-re-proxy: replay redis pool = 32 connections (--replay-redis-pool-size; default 8)\n"
                       "mcp-re-proxy: async fleet serving on 127.0.0.1:1 (1 cores)\n")
        assert startup_facts(log) == {"launches": 1, "replay_pool": [32], "replay_tier": ["REDIS_WAIT_QUORUM"]}
        assert startup_facts(Path(tmp) / "absent.log")["replay_pool"] == []


def declared_identity() -> None:
    """Identity: a 16-vCPU or arm64 host is not the declared context."""
    facts = {"vcpus_usable": 16, "vcpus_online": 16, "architecture": "aarch64", "mem_total_kib": 64 * 1024 * 1024}
    problems = check_expected(facts, 32, "x86_64", 128)
    assert len(problems) == 4, problems


def run_units() -> None:
    curves()
    attribution()
    rep_validation_and_rig_verdicts()
    isolation_plan()
    active_cpu_needs_activity()
    stage_timers_and_replication()
    ceiling_statements()
    replay_store_queueing()
    declared_identity()
