# SPDX-License-Identifier: Apache-2.0
"""What the replay tier's primary sees of the proxy's connection pool, around one point.

Under `redis-wait-quorum`, Redis does not run a client's next pipelined command while that
client is blocked in WAIT, so a pool's connections are the queues admissions wait in. This
module samples them from the server side over its own connection, standard library only:

  * every 0.25 s, CLIENT LIST rows whose last command was SET or WAIT (the replay store's
    two commands): how many such connections exist, how many are blocked (flag `b`), and
    their query-buffer bytes — the pipelined work queued behind a WAIT;
  * INFO clients / commandstats: blocked_clients and the cumulative SET and WAIT calls;
  * INFO replication: the primary's `master_repl_offset` and, per replica, the offset it has
    ACKNOWLEDGED and the seconds since its last ack. The byte gap between the two is the
    replication backlog a `WAIT` is waiting out; it is what separates "the replicas are slow
    to acknowledge" from "the pool's connections are all occupied".

Its own connection and any replica link are excluded. `config_get` records the tier's
configuration once. Nothing here changes what the proxy sends.
"""

from __future__ import annotations

import json
import socket
import statistics
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

STORE_COMMANDS = {"set", "wait"}
SAMPLE_PERIOD_S = 0.25


def endpoint(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    return parsed.hostname or "127.0.0.1", parsed.port or 6379


class Conn:
    """A minimal RESP2 client: one socket, blocking, enough for INFO / CLIENT / CONFIG."""

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def close(self) -> None:
        self.sock.close()

    def _fill(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("redis closed the connection")
        self.buf += chunk

    def _line(self) -> bytes:
        while b"\r\n" not in self.buf:
            self._fill()
        line, _, self.buf = self.buf.partition(b"\r\n")
        return line

    def reply(self):
        line = self._line()
        kind, rest = line[:1], line[1:]
        if kind == b"+":
            return rest.decode()
        if kind == b"-":
            raise RuntimeError(rest.decode())
        if kind == b":":
            return int(rest)
        if kind == b"$":
            n = int(rest)
            if n < 0:
                return None
            while len(self.buf) < n + 2:
                self._fill()
            data, self.buf = self.buf[:n], self.buf[n + 2:]
            return data.decode(errors="replace")
        if kind == b"*":
            return [self.reply() for _ in range(int(rest))]
        raise ValueError(f"unexpected RESP reply {line[:40]!r}")

    def call(self, *args: str):
        out = [f"*{len(args)}\r\n".encode()]
        for arg in args:
            data = arg.encode()
            out.append(f"${len(data)}\r\n".encode() + data + b"\r\n")
        self.sock.sendall(b"".join(out))
        return self.reply()

    def text(self, *args: str) -> str:
        value = self.call(*args)
        if not isinstance(value, str):
            raise ValueError(f"{args[0]} returned {type(value).__name__}, not text")
        return value


def parse_info(text: str) -> dict[str, str]:
    return dict(line.split(":", 1) for line in text.splitlines() if ":" in line and not line.startswith("#"))


def store_clients(listing: str, exclude: set[str]) -> list[dict]:
    """CLIENT LIST rows of the replay store's connections: last command SET or WAIT, not a
    replica (flag S), not an excluded id."""
    rows = []
    for line in listing.splitlines():
        fields = dict(kv.split("=", 1) for kv in line.split(" ") if "=" in kv)
        if fields.get("id") in exclude or "S" in fields.get("flags", ""):
            continue
        if fields.get("cmd") in STORE_COMMANDS:
            rows.append({"flags": fields.get("flags", ""), "qbuf": int(fields.get("qbuf", "0"))})
    return rows


def replication(info: dict[str, str]) -> dict:
    """The primary's offset and each replica's acknowledged offset, gap and ack age."""
    master = int(info.get("master_repl_offset", "0"))
    replicas = []
    for key in sorted(k for k in info if k.startswith("slave") and k[5:].isdigit()):
        fields = dict(kv.split("=", 1) for kv in info[key].split(",") if "=" in kv)
        offset = int(fields.get("offset", "0"))
        replicas.append({"port": int(fields.get("port", "0")), "offset": offset, "gap_bytes": master - offset,
                         "ack_age_s": int(fields.get("lag", "0"))})
    return {"master_offset": master, "replicas": replicas}


def calls(info: dict[str, str], command: str) -> int:
    stat = info.get(f"cmdstat_{command}", "")
    fields = dict(kv.split("=", 1) for kv in stat.split(",") if "=" in kv)
    return int(fields.get("calls", "0"))


def set_calls(url: str) -> int | None:
    """The primary's cumulative SET count now (INFO commandstats), or None if unreadable."""
    try:
        conn = Conn(*endpoint(url))
        try:
            return calls(parse_info(conn.text("INFO", "commandstats")), "set")
        finally:
            conn.close()
    except (OSError, RuntimeError, ValueError):
        return None


def config_get(url: str) -> dict:
    """CONFIG GET * of one node, or the reason it could not be read."""
    try:
        conn = Conn(*endpoint(url))
        try:
            flat = conn.call("CONFIG", "GET", "*")
        finally:
            conn.close()
    except (OSError, RuntimeError, ValueError) as exc:
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}
    if not isinstance(flat, list):
        return {"available": False, "reason": f"CONFIG GET returned {type(flat).__name__}"}
    return {"available": True, "config": dict(zip(flat[::2], flat[1::2]))}


class Sampler(threading.Thread):
    def __init__(self, url: str, out: Path, period: float = SAMPLE_PERIOD_S):
        super().__init__(daemon=True)
        self.url, self.out, self.period = url, out, period
        self.stop_event = threading.Event()
        self.samples: list[dict] = []
        self.error: str | None = None

    def run(self) -> None:
        try:
            conn = Conn(*endpoint(self.url))
        except OSError as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            return
        try:
            me = {str(conn.call("CLIENT", "ID"))}
            with open(self.out, "w") as sink:
                while not self.stop_event.wait(self.period):
                    t = time.time()
                    info = parse_info(conn.text("INFO", "clients") + "\n" + conn.text("INFO", "commandstats"))
                    repl = replication(parse_info(conn.text("INFO", "replication")))
                    rows = store_clients(conn.text("CLIENT", "LIST"), me)
                    sample = {"t": t, "blocked_clients": int(info.get("blocked_clients", "0")),
                              "store_conns": len(rows), "store_blocked": sum("b" in r["flags"] for r in rows),
                              "qbuf": [r["qbuf"] for r in rows],
                              "set_calls": calls(info, "set"), "wait_calls": calls(info, "wait"),
                              "repl": repl}
                    sink.write(json.dumps(sample) + "\n")
                    self.samples.append(sample)
        except (OSError, RuntimeError, ValueError) as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            conn.close()


def summarize(samples: list[dict]) -> dict:
    """Pool occupancy and queueing over the samples given (already cut to a window)."""
    if len(samples) < 2:
        return {"available": False, "reason": f"{len(samples)} sample(s) in the window"}
    span = samples[-1]["t"] - samples[0]["t"]
    loaded = [s for s in samples if s["store_conns"]]
    per_conn = [statistics.mean(s["qbuf"]) for s in loaded]
    return {
        "available": True, "samples": len(samples),
        "store_conns_max": max(s["store_conns"] for s in samples),
        "store_conns_mean": statistics.mean(s["store_conns"] for s in samples),
        "blocked_in_wait_mean": statistics.mean(s["store_blocked"] for s in samples),
        "blocked_fraction_mean": statistics.mean(s["store_blocked"] / s["store_conns"] for s in loaded) if loaded else None,
        "qbuf_per_conn_mean_bytes": statistics.mean(per_conn) if per_conn else None,
        "qbuf_max_bytes": max((max(s["qbuf"]) for s in loaded), default=0),
        "set_per_s": (samples[-1]["set_calls"] - samples[0]["set_calls"]) / span if span > 0 else None,
        "wait_per_s": (samples[-1]["wait_calls"] - samples[0]["wait_calls"]) / span if span > 0 else None,
        "replica_gap_bytes": _replica_gaps(samples),
    }


def _replica_gaps(samples: list[dict]) -> list[dict]:
    """Per replica port: mean and peak unacknowledged bytes, peak ack age."""
    by_port: dict[int, list[dict]] = {}
    for s in samples:
        for r in (s.get("repl") or {}).get("replicas", []):
            by_port.setdefault(r["port"], []).append(r)
    return [{"port": port, "gap_mean": statistics.mean(r["gap_bytes"] for r in rows),
             "gap_max": max(r["gap_bytes"] for r in rows), "ack_age_max_s": max(r["ack_age_s"] for r in rows)}
            for port, rows in sorted(by_port.items())]


class Window:
    """Context manager: a Sampler around one point, summarized over the measurement windows."""

    def __init__(self, url: str, point_dir: Path):
        self.sampler = Sampler(url, point_dir / "redis-queue.jsonl")

    def __enter__(self) -> "Window":
        self.sampler.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.sampler.stop_event.set()
        self.sampler.join(timeout=10)

    def summary(self, windows: list[list[float]]) -> dict:
        if self.sampler.error and not self.sampler.samples:
            return {"available": False, "reason": self.sampler.error}
        inside = [s for s in self.sampler.samples if any(a <= s["t"] <= b for a, b in windows)]
        return summarize(inside)
