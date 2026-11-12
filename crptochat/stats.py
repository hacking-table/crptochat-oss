"""Aggregate statistics for the operator dashboard.

Privacy rule: a snapshot contains counts and resource usage only. It never
carries a nickname, a channel name, an address or anything derived from
message content, so the dashboard cannot be used to watch people.

Snapshots are pushed once per second over a Unix socket inside the data
directory (mode 0600), reachable only by the user that runs the server.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections import deque

from . import __version__

HISTORY = 120
SOCKET_NAME = "stats.sock"
_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def socket_path(data_dir: str) -> str:
    return os.path.join(data_dir, SOCKET_NAME)


def _rss() -> int:
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * _PAGE
    except (OSError, ValueError, IndexError):
        return 0


def _fds() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return 0


def _meminfo() -> tuple[int, int]:
    total = avail = 0
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return total, avail


def snapshot(server, rates: dict | None = None, res: dict | None = None, hist: dict | None = None) -> dict:
    """Numbers only. Keep it that way."""
    sizes = [len(members) for members in server.members.values()]
    buckets = [0, 0, 0, 0]  # channels with 1, 2-5, 6-20, 21+ people online
    for size in sizes:
        buckets[0 if size <= 1 else 1 if size <= 5 else 2 if size <= 20 else 3] += 1
    registered, private = server.db.execute("SELECT COUNT(*), COALESCE(SUM(private), 0) FROM channels").fetchone()
    nicks = server.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    c = server.counters
    return {
        "v": 1,
        "version": __version__,
        "tls": server.tls,
        "uptime": int(time.time() - server.started),
        "conn": {"open": server.open_conns, "auth": len(server.sessions), "peak": server.peak_sessions,
                 "accepted": c["accepted"], "auth_fail": c["auth_fail"],
                 "guests": sum(1 for s in server.sessions.values() if s.guest),
                 "kicks": c["kicks"], "bans": c["bans"]},
        "nicks": {"registered": nicks, "new": c["registered"]},
        "chan": {"registered": registered, "private": private, "open": registered - private,
                 "active": len(sizes), "largest": max(sizes, default=0), "memberships": sum(sizes),
                 "buckets": buckets},
        "traffic": {"chan_msgs": c["chan_msgs"], "directs": c["directs"], "deliveries": c["deliveries"],
                    "bytes_in": c["bytes_in"], "bytes_out": c["bytes_out"], "refused": c["refused"],
                    "rate_limited": c["rate_limited"],
                    "rate": rates or {"msgs": 0.0, "directs": 0.0, "in": 0.0, "out": 0.0}},
        "res": res or {},
        "hist": hist or {},
    }


class StatsFeed:
    def __init__(self, server, path: str):
        self.server = server
        self.path = path
        self.latest = b""
        self._hist = {key: deque(maxlen=HISTORY) for key in ("auth", "msgs", "cpu", "kbps")}
        self._listener: asyncio.AbstractServer | None = None
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        old = os.umask(0o177)
        try:
            self._listener = await asyncio.start_unix_server(self._client, self.path)
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)
        self.sample(1.0, dict(self.server.counters), time.process_time(), 0.0)
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        if self._listener:
            self._listener.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def sample(self, elapsed: float, before: dict, cpu_before: float, lag: float) -> None:
        c = self.server.counters
        rates = {
            "msgs": (c["chan_msgs"] - before["chan_msgs"]) / elapsed,
            "directs": (c["directs"] - before["directs"]) / elapsed,
            "in": (c["bytes_in"] - before["bytes_in"]) / elapsed,
            "out": (c["bytes_out"] - before["bytes_out"]) / elapsed,
        }
        cpu = max(0.0, (time.process_time() - cpu_before) / elapsed * 100)
        total, avail = _meminfo()
        try:
            load = list(os.getloadavg())
        except OSError:
            load = [0.0, 0.0, 0.0]
        try:
            db_bytes = os.path.getsize(os.path.join(self.server.data_dir, "registry.db"))
        except OSError:
            db_bytes = 0
        res = {"cpu": round(cpu, 1), "rss": _rss(), "fds": _fds(), "threads": threading.active_count(),
               "load": [round(x, 2) for x in load], "ncpu": os.cpu_count() or 1, "lag_ms": round(lag * 1000, 1),
               "db_bytes": db_bytes, "mem_total": total, "mem_avail": avail}
        self._hist["auth"].append(len(self.server.sessions))
        self._hist["msgs"].append(round(rates["msgs"] + rates["directs"], 1))
        self._hist["cpu"].append(res["cpu"])
        self._hist["kbps"].append(round((rates["in"] + rates["out"]) / 1024, 1))
        rates = {key: round(value, 1) for key, value in rates.items()}
        snap = snapshot(self.server, rates, res, {key: list(values) for key, values in self._hist.items()})
        self.latest = json.dumps(snap, separators=(",", ":")).encode() + b"\n"

    async def _loop(self) -> None:
        while True:
            before, cpu_before, start = dict(self.server.counters), time.process_time(), time.monotonic()
            await asyncio.sleep(1)
            elapsed = time.monotonic() - start
            try:
                self.sample(elapsed, before, cpu_before, max(0.0, elapsed - 1))
            except Exception:  # the dashboard must never take the relay down
                pass

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Write-only feed: whatever the peer sends is ignored.
        try:
            while True:
                writer.write(self.latest)
                await writer.drain()
                await asyncio.sleep(1)
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
