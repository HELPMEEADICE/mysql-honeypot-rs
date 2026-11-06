#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Repeatable measurements for mysql-honeypot-rs.

Every number this script prints is measured on the machine that ran it; nothing
is hard-coded. It starts the release binary on an ephemeral port with a temporary
configuration and then reports:

  * idle resident set size,
  * resident set size with 100 and 256 concurrent authenticated sessions,
  * the observed login-delay distribution,
  * SQL query throughput (one connection, then many),
  * SQLite row-write throughput,
  * the size of the audit database,
  * stability under malformed packets, a connection burst and abrupt disconnect.

Usage
-----
    cargo build --release --locked
    python scripts/bench.py                 # full run
    python scripts/bench.py --quick         # smaller connection counts
    python scripts/bench.py --json          # machine-readable summary

The script speaks the MySQL protocol directly over TCP; it needs no driver and
no third-party package. It never touches a database other than the temporary one
it creates.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Iterable

READ_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Minimal MySQL client (protocol 10 / 4.1, text protocol)
# ---------------------------------------------------------------------------


class Client:
    """A tiny blocking MySQL client: handshake, COM_QUERY, text result sets."""

    def __init__(self, host: str, port: int, username: str = "bench", plugin: str | None = None):
        self.sock = socket.create_connection((host, port), timeout=READ_TIMEOUT)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sequence = 0
        self._handshake(username, plugin)

    # -- framing ----------------------------------------------------------
    def _read_exact(self, count: int) -> bytes:
        buffer = b""
        while len(buffer) < count:
            chunk = self.sock.recv(count - len(buffer))
            if not chunk:
                raise ConnectionError("peer closed the connection")
            buffer += chunk
        return buffer

    def _read_packet(self) -> bytes:
        header = self._read_exact(4)
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        self.sequence = (header[3] + 1) & 0xFF
        return self._read_exact(length) if length else b""

    def _write_packet(self, payload: bytes) -> None:
        header = struct.pack("<I", len(payload))[:3] + bytes([self.sequence & 0xFF])
        self.sequence = (self.sequence + 1) & 0xFF
        self.sock.sendall(header + payload)

    # -- handshake --------------------------------------------------------
    def _handshake(self, username: str, plugin: str | None) -> None:
        greeting = self._read_packet()
        assert greeting[0] == 10, f"unexpected protocol version {greeting[0]}"
        cursor = 1
        while greeting[cursor] != 0:
            cursor += 1
        self.server_version = greeting[1:cursor].decode("utf-8", "replace")
        cursor += 1
        cursor += 4  # connection id
        cursor += 8  # salt part 1
        cursor += 1  # filler
        capabilities_low = struct.unpack("<H", greeting[cursor : cursor + 2])[0]
        cursor += 2 + 1 + 2  # capabilities low, charset, status
        capabilities_high = struct.unpack("<H", greeting[cursor : cursor + 2])[0]
        server_capabilities = capabilities_low | (capabilities_high << 16)

        # CLIENT_PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH |
        # PLUGIN_AUTH_LENENC_CLIENT_DATA, intersected with what the server offers.
        capabilities = 0x0000_0200 | 0x0000_8000 | 0x0008_0000 | 0x0020_0000
        capabilities &= server_capabilities
        payload = struct.pack("<IIB", capabilities, 16 * 1024 * 1024, 45) + b"\x00" * 23
        payload += username.encode() + b"\x00"
        auth = b"\x00" * 32
        payload += bytes([len(auth)]) + auth
        if plugin:
            payload += plugin.encode() + b"\x00"
        self.sequence = 1
        self._write_packet(payload)

        response = self._read_packet()
        if response[0] == 0x01:  # AuthMoreData (caching_sha2_password fast path)
            response = self._read_packet()
        if response[0] != 0x00:
            raise RuntimeError(f"authentication refused: {response[:64]!r}")

    # -- commands ---------------------------------------------------------
    def query(self, sql: str) -> tuple[int, int]:
        """Run one statement; return `(columns, rows)` for a result set, `(0, affected)` for OK."""
        self.sequence = 0
        self._write_packet(b"\x03" + sql.encode())
        first = self._read_packet()
        if not first:
            return (0, 0)
        if first[0] == 0x00:
            cursor = 1
            affected, cursor = self._lenenc(first, cursor)
            return (0, affected)
        if first[0] == 0xFF:
            code = struct.unpack("<H", first[1:3])[0]
            raise RuntimeError(f"SQL error {code}: {first[3:]!r}")
        count, _ = self._lenenc(first, 0)
        for _ in range(count):
            self._read_packet()
        rows = 0
        while True:
            packet = self._read_packet()
            if packet and packet[0] == 0xFE and len(packet) < 9:
                break
            rows += 1
        return (count, rows)

    def ping(self) -> bool:
        self.sequence = 0
        self._write_packet(b"\x0e")
        return self._read_packet()[0] == 0x00

    def close(self) -> None:
        try:
            self.sequence = 0
            self._write_packet(b"\x01")
        except OSError:
            pass
        finally:
            try:
                self.sock.close()
            except OSError:
                pass

    @staticmethod
    def _lenenc(payload: bytes, cursor: int) -> tuple[int, int]:
        first = payload[cursor]
        if first < 0xFB:
            return (first, cursor + 1)
        if first == 0xFC:
            return (struct.unpack("<H", payload[cursor + 1 : cursor + 3])[0], cursor + 3)
        if first == 0xFD:
            value = int.from_bytes(payload[cursor + 1 : cursor + 4], "little")
            return (value, cursor + 4)
        return (struct.unpack("<Q", payload[cursor + 1 : cursor + 9])[0], cursor + 9)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def rss_kib(pid: int) -> int | None:
    """Resident set size of `pid`, or None when the platform does not expose it."""
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        except OSError:
            return None
        return None
    if sys.platform == "win32":
        # `tasklist` is present on every Windows install; parse its CSV output.
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            fields = [field.strip('"') for field in out.split('","')]
            if len(fields) >= 5:
                return int(fields[4].replace(",", "").replace(" K", ""))
        except (OSError, ValueError):
            return None
        return None
    return None


def wait_for_port(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"the honeypot never listened on {host}:{port}")


class Honeypot:
    def __init__(self, binary: str, workdir: str, delay_min: int, delay_max: int,
                 max_connections: int, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port = self._free_port()
        # Forward slashes on purpose: a Windows path inside a TOML basic string
        # would be read as a chain of escape sequences (`\U`, `\t`, ...).
        self.database = os.path.join(workdir, "honeypot.db").replace("\\", "/")
        config = os.path.join(workdir, "bench.toml")
        with open(config, "w", encoding="utf-8") as handle:
            handle.write(
                f"""[server]
host = "{host}"
port = {self.port}
version = "8.0.36"
max_connections = {max_connections}
idle_timeout_seconds = 300
handshake_timeout_seconds = 10
max_packet_size = 1048576
max_sql_length = 16384
shutdown_grace_seconds = 5

[authentication]
always_accept = true
delay_min_ms = {delay_min}
delay_max_ms = {delay_max}

[database]
sqlite_path = "{self.database}"
enable_wal = true
queue_capacity = 4096
busy_timeout_ms = 5000

[logging]
level = "warn"
log_queries = false

[virtualdb]
enabled = true
"""
            )
        self.log = open(os.path.join(workdir, "honeypot.log"), "wb")
        self.process = subprocess.Popen(
            [binary, "--config", config],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        wait_for_port(self.host, self.port)

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def client(self, username: str = "bench") -> Client:
        return Client(self.host, self.port, username)

    def stop(self) -> None:
        try:
            self.process.terminate()
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        finally:
            self.log.close()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def timed(fn, *args, **kwargs) -> float:
    start = time.perf_counter()
    fn(*args, **kwargs)
    return time.perf_counter() - start


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------


def measure_idle(honeypot: Honeypot, settle: float = 1.5) -> dict:
    time.sleep(settle)
    rss = rss_kib(honeypot.process.pid)
    return {"idle_rss_kib": rss}


def measure_connections(honeypot: Honeypot, count: int, username: str) -> dict:
    clients: list[Client] = []
    delays: list[float] = []
    try:
        for index in range(count):
            start = time.perf_counter()
            clients.append(honeypot.client(f"{username}{index}"))
            delays.append(time.perf_counter() - start)
        # Let the sessions settle so the RSS figure is not taken mid-handshake.
        time.sleep(0.5)
        rss = rss_kib(honeypot.process.pid)
        return {
            "sessions": count,
            "rss_kib": rss,
            "login_ms_min": round(min(delays) * 1000, 1) if delays else None,
            "login_ms_p50": round(percentile(delays, 0.50) * 1000, 1) if delays else None,
            "login_ms_p95": round(percentile(delays, 0.95) * 1000, 1) if delays else None,
            "login_ms_max": round(max(delays) * 1000, 1) if delays else None,
        }
    finally:
        for client in clients:
            client.close()


def measure_query_throughput(honeypot: Honeypot, statements: int) -> dict:
    client = honeypot.client("throughput")
    try:
        # Warm up: the first statement pays for the schema lookup.
        client.query("SELECT 1")
        elapsed = timed(lambda: [client.query("SELECT 1") for _ in range(statements)])
        single = statements / elapsed
        elapsed = timed(
            lambda: [client.query("SELECT COUNT(*) FROM users") for _ in range(statements)]
        )
        aggregate = statements / elapsed
        elapsed = timed(
            lambda: [
                client.query("SELECT username FROM users WHERE role = 'user'") for _ in range(statements)
            ]
        )
        filtered = statements / elapsed
        return {
            "select_1_per_s": round(single),
            "count_per_s": round(aggregate),
            "where_per_s": round(filtered),
        }
    finally:
        client.close()


def measure_concurrent_queries(honeypot: Honeypot, workers: int, per_worker: int) -> dict:
    import threading

    results: list[int] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        try:
            client = honeypot.client(f"load{index}")
            done = 0
            for _ in range(per_worker):
                client.query("SELECT 1")
                done += 1
            client.close()
        except Exception as error:  # noqa: BLE001 - a bench must report, not crash
            with lock:
                errors.append(repr(error))
            return
        with lock:
            results.append(done)

    started = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(index,)) for index in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started
    return {
        "workers": workers,
        "queries": sum(results),
        "errors": errors[:3],
        "queries_per_s": round(sum(results) / elapsed) if elapsed > 0 else 0,
    }


def measure_sqlite_writes(honeypot: Honeypot, statements: int) -> dict:
    client = honeypot.client("writer")
    try:
        elapsed = timed(
            lambda: [client.query(f"SELECT /* {index} */ 1") for index in range(statements)]
        )
        # The writer is asynchronous; give the queue a moment to drain.
        time.sleep(1.0)
        return {
            "statements": statements,
            "rows_per_s": round(statements / elapsed) if elapsed > 0 else 0,
            "database_bytes": os.path.getsize(honeypot.database)
            if os.path.exists(honeypot.database)
            else 0,
        }
    finally:
        client.close()


def measure_hostile_traffic(honeypot: Honeypot, rounds: int) -> dict:
    """Garbage framing, truncated handshakes, bursts and abrupt disconnects."""
    survived = 0
    for index in range(rounds):
        try:
            with socket.create_connection((honeypot.host, honeypot.port), timeout=5) as raw:
                if index % 3 == 0:
                    raw.sendall(bytes([0x41] * 128))
                elif index % 3 == 1:
                    raw.sendall(b"\xff\xff\xff\x00" + bytes([0x02] * 16))
                else:
                    raw.sendall(struct.pack("<I", 32))
                raw.close()
            survived += 1
        except OSError:
            pass
    # Sudden disconnects right after the handshake.
    for index in range(rounds // 2):
        try:
            client = honeypot.client(f"abrupt{index}")
            client.sock.close()
        except OSError:
            pass
    time.sleep(0.5)
    client = honeypot.client("after-hostile")
    try:
        healthy = client.ping()
    finally:
        client.close()
    return {"rounds": rounds, "accepted": survived, "still_serving": healthy}


def database_summary(path: str) -> dict:
    """Row counts straight from the SQLite file, read-only, without a driver."""
    if not os.path.exists(path):
        return {"error": "database missing"}
    try:
        import sqlite3

        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            connections = connection.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            queries = connection.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        finally:
            connection.close()
        return {
            "connections": connections,
            "queries": queries,
            "database_bytes": os.path.getsize(path),
        }
    except Exception as error:  # noqa: BLE001
        return {"error": repr(error)}


def binary_size(binary: str) -> int:
    return os.path.getsize(binary)


def block(title: str) -> None:
    print(f"\n=== {title} ===")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure mysql-honeypot-rs.")
    parser.add_argument("--binary", default=os.path.join("target", "release", "mysql-honeypot-rs"))
    parser.add_argument("--quick", action="store_true", help="smaller connection counts")
    parser.add_argument("--json", action="store_true", help="print one JSON object at the end")
    parser.add_argument("--statements", type=int, default=2000)
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
    arguments = parser.parse_args(list(argv) if argv is not None else None)

    binary = arguments.binary
    if sys.platform == "win32" and not binary.endswith(".exe") and os.path.exists(binary + ".exe"):
        binary += ".exe"
    if not os.path.exists(binary):
        print(f"error: {binary} not found; run `cargo build --release --locked` first")
        return 2

    workdir = tempfile.mkdtemp(prefix="honeypot-bench-")
    report: dict = {"binary": binary, "binary_bytes": binary_size(binary)}
    try:
        block("idle")
        # A dedicated instance with the shipped delay window, so the login-delay
        # distribution is measured against the real default (2-6 s).
        slow = Honeypot(binary, workdir, delay_min=2000, delay_max=6000, max_connections=64)
        try:
            report["idle"] = measure_idle(slow)
            print(f"  idle RSS: {report['idle']['idle_rss_kib']} KiB")
            block("login delay (default window 2000-6000 ms, 12 sessions)")
            logins = []
            for index in range(12):
                start = time.perf_counter()
                client = slow.client(f"delay{index}")
                logins.append(time.perf_counter() - start)
                client.close()
            report["login_delay_ms"] = {
                "min": round(min(logins) * 1000, 1),
                "p50": round(percentile(logins, 0.50) * 1000, 1),
                "p95": round(percentile(logins, 0.95) * 1000, 1),
                "max": round(max(logins) * 1000, 1),
            }
            print(f"  {report['login_delay_ms']}")
        finally:
            slow.stop()

        # A second instance with a near-zero delay so the load measurements are
        # not dominated by the trap.
        fast = Honeypot(binary, workdir, delay_min=1, delay_max=2, max_connections=320)
        try:
            counts = [100] if arguments.quick else [100, 256]
            for count in counts:
                block(f"{count} concurrent authenticated sessions")
                outcome = measure_connections(fast, count, f"s{count}_")
                report.setdefault("concurrency", []).append(outcome)
                print(f"  RSS: {outcome['rss_kib']} KiB, login p50 {outcome['login_ms_p50']} ms")

            block("single-connection query throughput")
            report["throughput"] = measure_query_throughput(fast, arguments.statements)
            print(f"  {report['throughput']}")

            block("32 workers x 100 statements")
            report["concurrent_throughput"] = measure_concurrent_queries(fast, 32, 100)
            print(f"  {report['concurrent_throughput']}")

            block("SQLite write throughput")
            report["logging"] = measure_sqlite_writes(fast, arguments.statements)
            print(f"  {report['logging']}")

            block("hostile traffic")
            report["hostile"] = measure_hostile_traffic(fast, 90 if arguments.quick else 180)
            print(f"  {report['hostile']}")
            report["database"] = database_summary(fast.database)
            print(f"  {report['database']}")
        finally:
            fast.stop()
    finally:
        if arguments.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print("\nAll figures above were measured by this run on this machine.")
        if not arguments.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"artifacts kept in {workdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
