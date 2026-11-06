#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# -*- coding: utf-8 -*-
"""End-to-end verification for a *running* MySQL honeypot.

The honeypot speaks the real MySQL 4.1 wire protocol but accepts any
credentials and answers with canned data.  This harness drives it from the
outside in three independent ways:

* ``pymysql``            - real driver, real handshake
* ``mysql.connector``    - second real driver (different client implementation)
* a hand rolled minimal MySQL 4.1 client over a raw socket (used for the
  authentication latency measurement and for malformed-packet fuzzing)

Finally it audits the SQLite log the honeypot writes (tables ``connections``
and ``queries``).

Importing this module performs no network and no file I/O: every connection is
created inside a check function, and execution is guarded by ``__main__``.

Examples
--------
    python scripts/e2e_clients.py
    python scripts/e2e_clients.py --host 127.0.0.1 --port 3306 --db ./honeypot.db
    python scripts/e2e_clients.py --skip-connector --json
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import secrets
import socket
import sqlite3
import struct
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------
# Timeouts (hard requirement: nothing may block forever)
# --------------------------------------------------------------------------
SOCKET_TIMEOUT = 15.0          # every socket read/write
CONNECT_TIMEOUT = 5.0          # TCP connect

MIN_DELAY_FLOOR = 1.8          # measured auth delay must also be >= this
DELAY_TOL_LOW = 0.25           # tolerance when auditing the logged delay
DELAY_TOL_HIGH = 1.0

# --------------------------------------------------------------------------
# MySQL capability flags (4.1 protocol)
# --------------------------------------------------------------------------
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000

CLIENT_CAPABILITIES = (
    CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
)

AUTH_PLUGIN_NAME = "caching_sha2_password"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _emit(text=""):
    """print() that never dies on a broken pipe."""
    try:
        print(text, flush=True)
    except (BrokenPipeError, OSError, UnicodeError):
        pass


def _result(status, lines):
    """Build a check result dict; ``lines`` is a list of detail strings."""
    if isinstance(lines, str):
        lines = [lines]
    return {"status": status, "detail": "\n".join(str(x) for x in lines)}


def _short(text, limit=200):
    text = "" if text is None else str(text)
    return text if len(text) <= limit else text[:limit] + "..."


def guarded(func):
    """Wrap a check so that *any* escape becomes a FAIL result, never a crash."""

    @functools.wraps(func)
    def wrapper(ctx):
        try:
            return func(ctx)
        except Exception as exc:
            return _result(FAIL, [
                "%s: %s" % (type(exc).__name__, exc),
                traceback.format_exc(limit=6).rstrip(),
            ])

    return wrapper


def _require_module(name):
    """Lazy import so that --help works even without the drivers."""
    import importlib

    try:
        return importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - environment specific
        raise RuntimeError("cannot import %r: %s: %s" % (name, type(exc).__name__, exc))


def build_test_credentials():
    """The three credential pairs required by the spec (all fake)."""
    random_tail = "pw_" + secrets.token_urlsafe(16)
    return [
        ("root", "wrongpassword"),
        ("admin", "123456"),
        ("test", random_tail),
    ]


# --------------------------------------------------------------------------
# Minimal MySQL 4.1 protocol client (raw socket)
# --------------------------------------------------------------------------
class WireError(Exception):
    """Protocol level failure inside the hand rolled client."""


class MySQLWireClient:
    """Just enough of the MySQL 4.1 client protocol for checks 3 and 8.

    Reads the initial handshake, sends a handshake response packet, then
    understands OK / ERR / AuthMoreData (0x01) / AuthSwitchRequest (0xfe).
    Sequence ids are tracked on both directions.
    """

    def __init__(self, host, port, connect_timeout=CONNECT_TIMEOUT, io_timeout=SOCKET_TIMEOUT):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.io_timeout = io_timeout
        self.sock = None
        self.next_seq = 0
        self.server_version = None
        self.server_capabilities = 0
        self.connection_id = 0
        self.salt = b""
        self.local_ip = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        return self.open()

    def __exit__(self, *_exc):
        self.close()
        return False

    def open(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        self.sock.settimeout(self.io_timeout)
        try:
            self.local_ip = self.sock.getsockname()[0]
        except OSError:
            self.local_ip = None
        return self

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # -- packet framing ----------------------------------------------------
    def _recv_exact(self, n):
        if n <= 0:
            return b""
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                raise WireError("socket timeout after %ss (wanted %d more bytes)" % (self.io_timeout, n - len(buf)))
            except OSError as exc:
                raise WireError("socket error: %s: %s" % (type(exc).__name__, exc))
            if not chunk:
                raise WireError("peer closed connection (got %d of %d bytes)" % (len(buf), n))
            buf += chunk
        return bytes(buf)

    def read_packet(self):
        """Return ``(seq, payload)`` and advance ``next_seq``."""
        header = self._recv_exact(4)
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        seq = header[3]
        payload = self._recv_exact(length) if length else b""
        # a 0xffffff length means "more packets follow for this payload"
        while length == 0xFFFFFF:
            header = self._recv_exact(4)
            length = header[0] | (header[1] << 8) | (header[2] << 16)
            seq = header[3]
            if length:
                payload += self._recv_exact(length)
        self.next_seq = (seq + 1) & 0xFF
        return seq, payload

    def write_packet(self, payload, seq=None):
        seq = self.next_seq if seq is None else seq
        n = len(payload)
        if n >= 0xFFFFFF:
            raise WireError("payload too large for one packet: %d" % n)
        header = bytes((n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, seq & 0xFF))
        try:
            self.sock.sendall(header + payload)
        except OSError as exc:
            raise WireError("send failed: %s: %s" % (type(exc).__name__, exc))
        self.next_seq = (seq + 1) & 0xFF
        return self.next_seq

    # -- handshake ---------------------------------------------------------
    def read_handshake(self):
        """Parse the server greeting; return it as a dict."""
        seq, payload = self.read_packet()
        if not payload:
            raise WireError("empty greeting packet")
        if payload[0] == 0xFF:
            raise WireError("server refused connection: %s" % self._err_text(payload))
        if payload[0] != 10:
            raise WireError("unexpected protocol version %d in greeting" % payload[0])

        pos = 1
        end = payload.find(b"\x00", pos)
        if end < 0:
            raise WireError("unterminated server version in greeting")
        self.server_version = payload[pos:end].decode("latin-1", "replace")
        pos = end + 1

        def take(n):
            nonlocal pos
            if pos + n > len(payload):
                raise WireError("greeting truncated (need %d bytes at offset %d of %d)" % (n, pos, len(payload)))
            chunk = payload[pos:pos + n]
            pos += n
            return chunk

        self.connection_id = struct.unpack("<I", take(4))[0]
        salt_part1 = take(8)
        take(1)  # filler
        lower = struct.unpack("<H", take(2))[0]
        if pos >= len(payload):
            self.server_capabilities = lower
            self.salt = salt_part1
            return self._greeting_dict()

        take(1)                                    # server charset
        take(2)                                    # status flags
        upper = struct.unpack("<H", take(2))[0]
        self.server_capabilities = (upper << 16) | lower
        auth_len = take(1)[0]
        take(10)                                   # reserved
        salt_part2 = b""
        if self.server_capabilities & CLIENT_SECURE_CONNECTION and pos < len(payload):
            want = max(13, auth_len - 8)
            salt_part2 = payload[pos:pos + want]
            salt_part2 = salt_part2.split(b"\x00", 1)[0]
        self.salt = (salt_part1 + salt_part2)[:20]
        return self._greeting_dict()

    def _greeting_dict(self):
        return {
            "server_version": self.server_version,
            "connection_id": self.connection_id,
            "capabilities": "0x%06x" % self.server_capabilities,
            "salt_len": len(self.salt),
            "seq": 0,
        }

    def build_handshake_response(self, user, auth_response=None, plugin=AUTH_PLUGIN_NAME):
        if auth_response is None:
            # 32 random bytes: the honeypot accepts anything, so a correct
            # caching_sha2_password scramble is not needed.
            auth_response = secrets.token_bytes(32)
        caps = CLIENT_CAPABILITIES
        body = bytearray()
        body += struct.pack("<I", caps)
        body += struct.pack("<I", 16 * 1024 * 1024)      # max packet size
        body += bytes((0x21,))                           # utf8_general_ci
        body += b"\x00" * 23                             # filler
        body += user.encode("utf-8") + b"\x00"
        body += bytes((len(auth_response),)) + auth_response   # lenenc auth data
        body += plugin.encode("ascii") + b"\x00"
        return bytes(body)

    # -- auth result -------------------------------------------------------
    def send_auth_response(self, user, password=""):
        """Send the handshake response; return the perf_counter() timestamp.

        ``password`` is accepted for readability only - the auth response is
        32 random bytes, because the honeypot authenticates any credential.
        """
        payload = self.build_handshake_response(user)
        self.write_packet(payload)          # uses next_seq == handshake_seq + 1
        return time.perf_counter()

    def wait_auth_result(self, started_at=None, max_packets=8):
        """Read until OK/ERR.  ``elapsed`` is measured from ``started_at``."""
        if started_at is None:
            started_at = time.perf_counter()
        stages = []
        status, detail = None, ""
        for _ in range(max_packets):
            seq, payload = self.read_packet()
            if not payload:
                raise WireError("empty packet while waiting for auth result")
            first = payload[0]
            if first == 0x00:
                status = "OK"
                detail = "OK packet seq=%d len=%d" % (seq, len(payload))
                break
            if first == 0xFF:
                status = "ERR"
                detail = "ERR packet: %s" % self._err_text(payload)
                break
            if first == 0x01:                     # AuthMoreData
                stage = payload[1] if len(payload) > 1 else -1
                stages.append("AuthMoreData(0x%02x)" % (stage & 0xFF))
                if stage == 0x04:                 # full authentication requested
                    self.write_packet(secrets.token_bytes(32))
                continue
            if first == 0xFE:                     # AuthSwitchRequest
                rest = payload[1:]
                info = rest.split(b"\x00", 1)[0].decode("latin-1", "replace")
                stages.append("AuthSwitchRequest(%s)" % (info or "?"))
                self.write_packet(secrets.token_bytes(20))
                continue
            raise WireError("unexpected auth packet 0x%02x" % first)
        elapsed = time.perf_counter() - started_at
        if status is None:
            raise WireError("no OK/ERR after %d auth packets" % max_packets)
        return {"status": status, "elapsed": elapsed, "detail": detail, "stages": stages}

    @staticmethod
    def _err_text(payload):
        if len(payload) < 3:
            return "<short err packet>"
        code = struct.unpack_from("<H", payload, 1)[0]
        text = payload[3:]
        if text[:1] == b"#":
            text = text[6:]
        return "%d %s" % (code, text.decode("utf-8", "replace"))


# --------------------------------------------------------------------------
# Context shared by the checks
# --------------------------------------------------------------------------
class Ctx:
    def __init__(self, args):
        self.args = args
        self.host = args.host
        self.port = args.port
        self.delay_min = float(args.delay_min)
        self.delay_max = float(args.delay_max)
        self.concurrency = int(args.concurrency)
        self.db_path = args.db
        self.used_users = []
        self.used_sql = []
        self.local_ip = None
        self.observed = {}

    def note_user(self, user):
        if user not in self.used_users:
            self.used_users.append(user)

    def note_sql(self, sql):
        text = " ".join(str(sql).split())
        if text not in self.used_sql:
            self.used_sql.append(text)


def _pymysql_connect(ctx, user, password):
    pymysql = _require_module("pymysql")
    kwargs = dict(
        host=ctx.host,
        port=ctx.port,
        user=user,
        password=password,
        connect_timeout=CONNECT_TIMEOUT,
        read_timeout=SOCKET_TIMEOUT,
        write_timeout=SOCKET_TIMEOUT,
        autocommit=True,
        charset="utf8mb4",
    )
    try:
        return pymysql.connect(**kwargs)
    except TypeError:
        # very old fork without read/write timeouts
        for key in ("read_timeout", "write_timeout", "charset"):
            kwargs.pop(key, None)
        return pymysql.connect(**kwargs)


def _fetch(ctx, conn, sql):
    """Run one statement on an open connection and return the rows."""
    ctx.note_sql(sql)
    cur = conn.cursor()
    try:
        cur.execute(sql)
        try:
            return cur.fetchall()
        except Exception:
            return None
    finally:
        try:
            cur.close()
        except Exception:
            pass


def _first_value(rows):
    if not rows:
        return None
    row = rows[0]
    if isinstance(row, (list, tuple)):
        return row[0] if row else None
    return row


def _probe_alive(ctx, retries=1, label="liveness"):
    """pymysql connect + SELECT 1; returns (ok, detail)."""
    last = "not attempted"
    for attempt in range(retries + 1):
        started = time.perf_counter()
        try:
            conn = _pymysql_connect(ctx, "root", "wrongpassword")
            try:
                rows = _fetch(ctx, conn, "SELECT 1")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            value = _first_value(rows)
            if value is not None and int(value) == 1:
                return True, "%s: SELECT 1 -> 1 (%.2fs, attempt %d)" % (
                    label, time.perf_counter() - started, attempt + 1)
            last = "SELECT 1 -> %r" % (value,)
        except Exception as exc:
            last = "%s: %s" % (type(exc).__name__, exc)
        if attempt < retries:
            time.sleep(1.0)
    return False, "%s: %s" % (label, last)


# ==========================================================================
# CHECK 1 - pymysql accepts any credentials
# ==========================================================================
def check_1_pymysql_any_credentials(ctx):
    lines, problems = [], []
    creds = build_test_credentials()
    for user, password in creds:
        ctx.note_user(user)
        started = time.perf_counter()
        try:
            conn = _pymysql_connect(ctx, user, password)
            try:
                rows = _fetch(ctx, conn, "SELECT 1")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            lines.append("%-6s / %-24s -> authenticated, SELECT 1 -> %r (%.2fs)" % (
                user, _short(password, 24), _first_value(rows), time.perf_counter() - started))
        except Exception as exc:
            problems.append("%s / %s -> %s: %s" % (user, password, type(exc).__name__, _short(exc, 160)))
    lines.extend(problems)
    total = len(creds)
    if not problems:
        return _result(PASS, lines + ["all %d/%d credential pairs accepted" % (total, total)])
    return _result(FAIL, lines + ["%d/%d credential pairs failed" % (len(problems), total)])


# ==========================================================================
# CHECK 2 - mysql.connector accepts any credentials
# ==========================================================================
def check_2_mysql_connector_any_credentials(ctx):
    if getattr(ctx.args, "skip_connector", False):
        return _result(SKIP, "--skip-connector given")
    connector = _require_module("mysql.connector")
    lines, problems = [], []
    creds = build_test_credentials()
    for user, password in creds:
        ctx.note_user(user)
        started = time.perf_counter()
        attempts = [
            ("default", dict()),
            ("auth_plugin=mysql_native_password", dict(auth_plugin="mysql_native_password")),
        ]
        last_exc, done = None, False
        for label, extra in attempts:
            kwargs = dict(
                host=ctx.host,
                port=ctx.port,
                user=user,
                password=password,
                connection_timeout=CONNECT_TIMEOUT,
            )
            kwargs.update(extra)          # never force sql_mode, never use prepared cursors
            try:
                conn = connector.connect(**kwargs)
                try:
                    cur = conn.cursor()   # plain text cursor
                    try:
                        ctx.note_sql("SELECT 1")
                        cur.execute("SELECT 1")
                        rows = cur.fetchall()
                    finally:
                        try:
                            cur.close()
                        except Exception:
                            pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                lines.append("%-6s / %-24s -> authenticated via %s, SELECT 1 -> %r (%.2fs)" % (
                    user, _short(password, 24), label, _first_value(rows), time.perf_counter() - started))
                done = True
                break
            except Exception as exc:
                last_exc = exc
                continue
        if not done:
            problems.append("%s / %s -> %s: %s" % (
                user, password, type(last_exc).__name__, _short(last_exc, 160)))
    lines.extend(problems)
    total = len(creds)
    if not problems:
        return _result(PASS, lines + ["all %d/%d credential pairs accepted by mysql.connector" % (total, total)])
    return _result(FAIL, lines + ["%d/%d credential pairs failed" % (len(problems), total)])


# ==========================================================================
# CHECK 3 - authentication delay window
# ==========================================================================
def check_3_auth_delay(ctx):
    lines, problems = [], []
    attempts = 0
    sample = None
    while attempts < 2 and sample is None:
        attempts += 1
        try:
            client = MySQLWireClient(ctx.host, ctx.port).open()
        except Exception as exc:
            problems.append("attempt %d: TCP connect failed: %s: %s" % (attempts, type(exc).__name__, exc))
            if attempts < 2:
                time.sleep(1.0)
            continue
        try:
            t_connect = time.perf_counter()
            greeting = client.read_handshake()
            t_greeting = time.perf_counter()
            ctx.note_user("root")
            t_sent = client.send_auth_response("root", password="wrongpassword")
            outcome = client.wait_auth_result(started_at=t_sent)
            sample = {
                "attempt": attempts,
                "greeting": greeting,
                "greeting_latency": t_greeting - t_connect,
                "response_send": t_sent - t_connect,
                "auth": outcome,
            }
        except Exception as exc:
            problems.append("attempt %d: %s: %s" % (attempts, type(exc).__name__, exc))
            if attempts < 2:
                time.sleep(1.0)
        finally:
            client.close()

    if sample is None:
        return _result(FAIL, problems + ["no raw-socket sample could be measured"])

    delay = sample["auth"]["elapsed"]
    lines.append("handshake: server=%r caps=%s salt=%dB conn_id=%d" % (
        sample["greeting"]["server_version"], sample["greeting"]["capabilities"],
        sample["greeting"]["salt_len"], sample["greeting"]["connection_id"]))
    lines.append("timeline: handshake-response sent at +%.3fs, greeting read at +%.3fs" % (
        sample["response_send"], sample["greeting_latency"]))
    lines.append("measured auth delay (send response -> final %s) = %.3f s (%d ms)" % (
        sample["auth"]["status"], delay, round(delay * 1000)))
    if sample["auth"]["stages"]:
        lines.append("auth packets before verdict: %s" % ", ".join(sample["auth"]["stages"]))
    lines.append("window: --delay-min=%.2fs --delay-max=%.2fs, floor=%.2fs" % (
        ctx.delay_min, ctx.delay_max, MIN_DELAY_FLOOR))
    ctx.observed["auth_delay_s"] = delay

    if sample["auth"]["status"] != "OK":
        problems.append("authentication did not end with OK: %s" % sample["auth"]["detail"])
    if delay < MIN_DELAY_FLOOR:
        problems.append("delay %.3fs is below the %.1fs floor" % (delay, MIN_DELAY_FLOOR))
    if not (ctx.delay_min <= delay <= ctx.delay_max):
        problems.append("delay %.3fs is outside [%.2f, %.2f]" % (delay, ctx.delay_min, ctx.delay_max))
        if sample["greeting_latency"] >= ctx.delay_min:
            lines.append(
                "NOTE: the greeting itself was delayed by %.3fs - if the server sleeps before "
                "sending the handshake, the delay is applied there instead of on the auth response"
                % sample["greeting_latency"])
    lines.extend(problems)
    return _result(FAIL if problems else PASS, lines)


# ==========================================================================
# CHECK 4 - SHOW DATABASES
# ==========================================================================
def check_4_show_databases(ctx):
    user, password = "root", "wrongpassword"
    ctx.note_user(user)
    conn = _pymysql_connect(ctx, user, password)
    try:
        rows = _fetch(ctx, conn, "SHOW DATABASES")
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if rows is None:
        return _result(FAIL, ["SHOW DATABASES returned no result set"])
    names = []
    for row in rows:
        value = row[0] if isinstance(row, (list, tuple)) else row
        if value is not None:
            names.append(str(value).strip())
    lowered = [n.lower() for n in names]
    lines = ["rows=%d" % len(names), "names=%s" % _short(", ".join(names), 400)]
    problems = []
    if len(names) < 5:
        problems.append("expected >= 5 databases, got %d" % len(names))
    for required in ("information_schema", "mysql", "performance_schema"):
        if required in lowered:
            lines.append("contains %s: yes" % required)
        else:
            lines.append("contains %s: NO" % required)
            problems.append("missing database %r" % required)
    lines.extend(problems)
    return _result(FAIL if problems else PASS, lines)


# ==========================================================================
# CHECK 5 - SELECT 1
# ==========================================================================
def check_5_select_one(ctx):
    user, password = "root", "wrongpassword"
    ctx.note_user(user)
    conn = _pymysql_connect(ctx, user, password)
    try:
        rows = _fetch(ctx, conn, "SELECT 1")
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if rows is None:
        return _result(FAIL, ["SELECT 1 returned no result set"])
    if len(rows) != 1:
        return _result(FAIL, ["SELECT 1 returned %d rows, expected exactly 1: %r" % (len(rows), rows)])
    row = rows[0]
    if not isinstance(row, (list, tuple)) or len(row) != 1:
        return _result(FAIL, ["SELECT 1 returned %d columns, expected exactly 1: %r" % (
            len(row) if hasattr(row, "__len__") else 1, row)])
    value = row[0]
    try:
        ok = int(value) == 1
    except (TypeError, ValueError):
        ok = value == 1
    lines = ["row=%r" % (row,)]
    if not ok:
        lines.append("value is not 1 (got %r)" % (value,))
        return _result(FAIL, lines)
    lines.append("value == 1")
    return _result(PASS, lines)


# ==========================================================================
# CHECK 6 - metadata functions do not raise
# ==========================================================================
def check_6_metadata_functions(ctx):
    user, password = "root", "wrongpassword"
    ctx.note_user(user)
    conn = _pymysql_connect(ctx, user, password)
    lines, problems = [], []
    try:
        for sql in ("SELECT VERSION()", "SELECT USER()", "SELECT DATABASE()"):
            try:
                rows = _fetch(ctx, conn, sql)
                lines.append("%-18s -> %r" % (sql, _first_value(rows)))
            except Exception as exc:
                problems.append("%s raised %s: %s" % (sql, type(exc).__name__, _short(exc, 140)))
    finally:
        try:
            conn.close()
        except Exception:
            pass
    lines.extend(problems)
    return _result(FAIL if problems else PASS, lines)


# ==========================================================================
# CHECK 7 - many statements on one connection
# ==========================================================================
MULTI_STATEMENTS = [
    "SHOW TABLES",
    "SHOW VARIABLES",
    "SELECT @@version",
    "CREATE TABLE t (a int)",
    "INSERT INTO t VALUES (1)",
    "DROP TABLE t",
]

_DEAD_CONNECTION_CODES = {0, 2006, 2012, 2013, 2055}


def _is_dead_connection(exc):
    name = type(exc).__name__
    if name in ("InterfaceError", "BrokenPipeError"):
        return True
    args = getattr(exc, "args", ()) or ()
    code = args[0] if args else None
    return code in _DEAD_CONNECTION_CODES


def check_7_multi_statement_session(ctx):
    user, password = "root", "wrongpassword"
    ctx.note_user(user)
    conn = _pymysql_connect(ctx, user, password)
    lines, problems = [], []
    attempted = 0
    dead = False
    try:
        for sql in MULTI_STATEMENTS:
            attempted += 1
            ctx.note_sql(sql)
            cur = None
            try:
                cur = conn.cursor()
                cur.execute(sql)
                try:
                    rows = cur.fetchall()
                except Exception:
                    rows = None
                lines.append("[%d] %-26s -> ok (%s)" % (
                    attempted, sql, "no result set" if rows is None else "%d rows" % len(rows)))
            except Exception as exc:
                lines.append("[%d] %-26s -> %s: %s" % (
                    attempted, sql, type(exc).__name__, _short(exc, 120)))
                if _is_dead_connection(exc):
                    dead = True
                    problems.append("connection died on %r (%s)" % (sql, type(exc).__name__))
                    break
            finally:
                if cur is not None:
                    try:
                        cur.close()
                    except Exception:
                        pass

        if not dead:
            try:
                rows = _fetch(ctx, conn, "SELECT 1")
                value = _first_value(rows)
                ok = False
                try:
                    ok = value is not None and int(value) == 1
                except (TypeError, ValueError):
                    ok = value == 1
                if ok:
                    lines.append("after %d statements the same connection still answers SELECT 1 -> 1" % attempted)
                else:
                    problems.append("SELECT 1 after the batch returned %r" % (value,))
            except Exception as exc:
                problems.append("SELECT 1 after the batch raised %s: %s" % (type(exc).__name__, _short(exc, 120)))
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if attempted < 5:
        problems.append("only %d statements were executed, need >= 5" % attempted)
    lines.extend(problems)
    return _result(FAIL if problems else PASS, lines)


# ==========================================================================
# CHECK 8 - malformed packets must not kill the server
# ==========================================================================
def _scenario_random_garbage(ctx):
    junk = secrets.token_bytes(200)
    with MySQLWireClient(ctx.host, ctx.port) as client:
        try:
            client.read_handshake()
        except Exception:
            pass
        try:
            client.sock.sendall(junk)
            return "sent 200 random bytes (no valid header): %s" % junk[:8].hex()
        except OSError as exc:
            return "server closed before the 200 garbage bytes were accepted: %s" % type(exc).__name__


def _scenario_huge_length_prefix(ctx):
    payload = b"\xff\xff\xff\x01" + secrets.token_bytes(10)   # claims 16 MiB, sends 10 bytes
    sock = socket.create_connection((ctx.host, ctx.port), timeout=CONNECT_TIMEOUT)
    try:
        sock.settimeout(SOCKET_TIMEOUT)
        try:
            sock.recv(4096)          # drain the greeting, ignore whatever arrives
        except OSError:
            pass
        sock.sendall(payload)
        return "declared length 0xFFFFFF then sent 10 bytes and closed"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _scenario_header_only(ctx):
    sock = socket.create_connection((ctx.host, ctx.port), timeout=CONNECT_TIMEOUT)
    try:
        sock.settimeout(SOCKET_TIMEOUT)
        try:
            sock.recv(4096)
        except OSError:
            pass
        sock.sendall(b"\x10\x00\x00\x01")     # header only: claims 16 bytes, sends none
        return "sent a bare 4-byte header (declares 16 bytes, none sent) and closed"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _scenario_unknown_command(ctx):
    client = MySQLWireClient(ctx.host, ctx.port).open()
    try:
        client.read_handshake()
        started = client.send_auth_response("root", password="wrongpassword")
        try:
            outcome = client.wait_auth_result(started_at=started)
            stage = outcome["status"]
        except Exception as exc:
            stage = "auth unfinished (%s)" % type(exc).__name__
        reply = "no reply"
        try:
            client.write_packet(b"\x7f" + b"\x00" * 8)     # 0x7f is not a valid command
            try:
                _seq, payload = client.read_packet()
                reply = "reply 0x%02x len=%d" % (payload[0], len(payload)) if payload else "empty reply"
            except Exception as exc:
                reply = "no reply (%s)" % type(exc).__name__
        except OSError:
            reply = "send failed (connection already closed)"
        return "valid handshake response (%s) then unknown command 0x7f: %s" % (stage, reply)
    finally:
        client.close()


def check_8_malformed_packets(ctx):
    scenarios = [
        ("a: 200 random bytes", _scenario_random_garbage),
        ("b: len prefix 0xFFFFFF + 10 bytes", _scenario_huge_length_prefix),
        ("c: bare 4-byte header", _scenario_header_only),
        ("d: valid auth then unknown cmd 0x7f", _scenario_unknown_command),
    ]
    lines, problems = [], []
    for label, fn in scenarios:
        try:
            note = fn(ctx)
            lines.append("%-38s sent  (%s)" % (label, _short(note, 120)))
        except Exception as exc:
            # a failure while *sending* is itself acceptable - the point is the
            # server surviving, which the liveness probe below decides.
            lines.append("%-38s send aborted: %s: %s" % (label, type(exc).__name__, _short(exc, 100)))
        ok, detail = _probe_alive(ctx, retries=1, label="after " + label)
        lines.append("%-38s probe %s (%s)" % (label, "alive" if ok else "DEAD", detail))
        if not ok:
            problems.append("server unresponsive after scenario %s" % label)
    lines.extend(problems)
    return _result(FAIL if problems else PASS, lines)


# ==========================================================================
# CHECK 9 - concurrency
# ==========================================================================
def _concurrent_worker(ctx, index):
    started = time.perf_counter()
    try:
        conn = _pymysql_connect(ctx, "root", "wrongpassword")
        try:
            rows = _fetch(ctx, conn, "SELECT 1")
        finally:
            try:
                conn.close()
            except Exception:
                pass
        value = _first_value(rows)
        ok = value is not None and int(value) == 1
        return ok, time.perf_counter() - started, "SELECT 1 -> %r" % (value,)
    except Exception as exc:
        return False, time.perf_counter() - started, "%s: %s" % (type(exc).__name__, _short(exc, 120))


def check_9_concurrency(ctx):
    workers = max(2, ctx.concurrency)
    ctx.note_user("root")
    lines, problems = [], []

    ref_started = time.perf_counter()
    try:
        conn = _pymysql_connect(ctx, "root", "wrongpassword")
        try:
            _fetch(ctx, conn, "SELECT 1")
        finally:
            try:
                conn.close()
            except Exception:
                pass
        reference = time.perf_counter() - ref_started
    except Exception as exc:
        return _result(FAIL, ["reference connection failed: %s: %s" % (type(exc).__name__, exc)])

    serial_estimate = reference * workers
    lines.append("reference single connection: %.2fs -> serial estimate for %d conns: %.2fs" % (
        reference, workers, serial_estimate))

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_concurrent_worker, ctx, i) for i in range(workers)]
        outcomes = [f.result() for f in futures]
    concurrent = time.perf_counter() - started

    ok_count = sum(1 for ok, _elapsed, _detail in outcomes if ok)
    elapsed_list = [round(elapsed, 2) for _ok, elapsed, _detail in outcomes]
    lines.append("%d/%d concurrent connections succeeded; per-connection wall time: %s" % (
        ok_count, workers, elapsed_list))
    lines.append("concurrent wall time: %.2fs vs serial estimate %.2fs (ratio %.2f)" % (
        concurrent, serial_estimate, (concurrent / serial_estimate) if serial_estimate else 0.0))
    for ok, _elapsed, detail in outcomes:
        if not ok:
            problems.append("worker failed: %s" % detail)
    if ok_count != workers:
        problems.append("%d of %d concurrent connections failed" % (workers - ok_count, workers))
    if serial_estimate > 0 and concurrent >= serial_estimate * 0.85:
        problems.append("concurrent run (%.2fs) is not clearly faster than the serial estimate (%.2fs)" % (
            concurrent, serial_estimate))
    lines.extend(problems)
    return _result(FAIL if problems else PASS, lines)


# ==========================================================================
# CHECK 10 - SQLite log audit
# ==========================================================================
def _open_sqlite_readonly(path):
    resolved = os.path.abspath(path).replace("\\", "/")
    if not resolved.startswith("/"):
        resolved = "/" + resolved
    uri = "file:" + resolved + "?mode=ro"
    try:
        return sqlite3.connect(uri, uri=True, timeout=5.0)
    except sqlite3.Error:
        return sqlite3.connect(path, timeout=5.0)


def _table_names(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return [str(row[0]) for row in rows]


def _pick_table(available, wanted):
    for name in available:
        if name.lower() == wanted:
            return name
    return None


def _table_columns(conn, table):
    quoted = '"' + table.replace('"', '""') + '"'
    rows = conn.execute("PRAGMA table_info(%s)" % quoted).fetchall()
    return [str(row[1]) for row in rows]


def _find_column(columns, patterns, exclude=()):
    for pattern in patterns:
        rx = re.compile(pattern, re.IGNORECASE)
        for column in columns:
            if any(re.search(bad, column, re.IGNORECASE) for bad in exclude):
                continue
            if rx.search(column):
                return column
    return None


def _distinct_values(conn, table, column, limit=200):
    quoted_t = '"' + table.replace('"', '""') + '"'
    quoted_c = '"' + column.replace('"', '""') + '"'
    sql = "SELECT DISTINCT %s FROM %s WHERE %s IS NOT NULL LIMIT %d" % (quoted_c, quoted_t, quoted_c, limit)
    try:
        return [row[0] for row in conn.execute(sql).fetchall()]
    except sqlite3.Error:
        return []


def _count_rows(conn, table):
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        return conn.execute("SELECT COUNT(*) FROM %s" % quoted).fetchone()[0]
    except sqlite3.Error as exc:
        return "error: %s" % exc


def _as_seconds(value):
    """auth_delay_ms may be stored in ms (expected) or in seconds."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number / 1000.0 if number >= 100 else number


def _looks_empty(value):
    if value is None:
        return True
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    text = str(value).strip()
    return text == "" or text in ("0", "0.0", "None", "null", "NULL")


def _candidate_ips(ctx):
    candidates = []
    if ctx.local_ip:
        candidates.append(ctx.local_ip)
    try:
        sock = socket.create_connection((ctx.host, ctx.port), timeout=CONNECT_TIMEOUT)
        try:
            # the honeypot logs the *peer* address, i.e. our local interface address
            candidates.append(sock.getsockname()[0])
        finally:
            sock.close()
    except OSError:
        pass
    for fallback in ("127.0.0.1", "::1", "localhost"):
        candidates.append(fallback)
    seen, ordered = set(), []
    for item in candidates:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def check_10_sqlite_log_audit(ctx):
    path = ctx.db_path
    if not path or not os.path.isfile(path):
        return _result(SKIP, "log database not found: %s (nothing to audit)" % os.path.abspath(path or "."))

    lines, problems = [], []
    try:
        conn = _open_sqlite_readonly(path)
    except sqlite3.Error as exc:
        return _result(FAIL, ["cannot open %s read-only: %s: %s" % (os.path.abspath(path), type(exc).__name__, exc)])
    try:
        tables = _table_names(conn)
        lines.append("db=%s tables=%s" % (os.path.abspath(path), tables))

        connections_table = _pick_table(tables, "connections")
        queries_table = _pick_table(tables, "queries")
        if connections_table is None:
            problems.append("table 'connections' is missing")
        if queries_table is None:
            problems.append("table 'queries' is missing")
        if connections_table:
            lines.append("connections COUNT(*) = %s" % _count_rows(conn, connections_table))
        if queries_table:
            lines.append("queries COUNT(*) = %s" % _count_rows(conn, queries_table))

        # ---------------- connections -------------------------------------
        if connections_table:
            columns = _table_columns(conn, connections_table)
            lines.append("connections columns: %s" % columns)
            user_col = _find_column(columns, (r"user", r"login", r"account"))
            ip_col = _find_column(columns, (r"ip", r"addr", r"host", r"remote", r"peer", r"client"))
            delay_col = _find_column(columns, (r"delay",))
            connected_col = _find_column(columns, (r"^connected.*(at|time|ts)$", r"^connect.*(at|time|ts)$",
                                                   r"^connected", r"^connect_"))
            authed_col = _find_column(columns, (r"^authenticated.*(at|time|ts)$",
                                                r"^auth.*(at|time|ts)$", r"^authenticated"),
                                      exclude=(r"delay",))

            if user_col is None:
                problems.append("connections has no username-like column")
            if delay_col is None:
                problems.append("connections has no auth_delay_ms-like column")
            if connected_col is None:
                problems.append("connections has no connected_at-like column")
            if authed_col is None:
                problems.append("connections has no authenticated_at-like column")

            # source IP recorded for this run
            if ip_col is not None:
                ips = [str(v) for v in _distinct_values(conn, connections_table, ip_col)]
                wanted = _candidate_ips(ctx)
                hit = None
                for value in ips:
                    for candidate in wanted:
                        if candidate and candidate in value:
                            hit = (value, candidate)
                            break
                    if hit:
                        break
                lines.append("source IP column %r values=%s (looking for %s)" % (
                    ip_col, _short(", ".join(ips[:10]), 200), wanted[:3]))
                if hit is None:
                    problems.append("no connections row for this run's source IP (%s)" % wanted[0])
                else:
                    lines.append("row for source IP %r found (matched %r)" % (hit[0], hit[1]))
            else:
                problems.append("connections has no source-IP-like column")

            # usernames used in this run
            if user_col is not None:
                names = [str(v) for v in _distinct_values(conn, connections_table, user_col)]
                lowered = [n.lower() for n in names]
                missing = [u for u in ctx.used_users if u.lower() not in lowered]
                lines.append("username column %r values=%s; tested=%s" % (
                    user_col, _short(", ".join(names[:10]), 200), ctx.used_users))
                if missing:
                    problems.append("usernames missing from the log: %s" % missing)
                else:
                    lines.append("all tested usernames present in the log")

            # auth_delay_ms within [delay_min, delay_max]
            if delay_col is not None:
                raw = _distinct_values(conn, connections_table, delay_col, limit=500)
                seconds = [(_as_seconds(v), v) for v in raw]
                seconds = [(s, v) for s, v in seconds if s is not None]
                lines.append("auth delay column %r raw values=%s" % (
                    delay_col, _short(", ".join(str(v) for v in raw[:10]), 200)))
                in_window = [s for s, _v in seconds
                             if ctx.delay_min - DELAY_TOL_LOW <= s <= ctx.delay_max + DELAY_TOL_HIGH]
                sec_text = ", ".join("%.3fs" % s for s, _v in seconds[:10])
                lines.append("auth delay in seconds=%s; window=[%.2f, %.2f] +/- tolerance" % (
                    _short(sec_text, 200), ctx.delay_min, ctx.delay_max))
                if not seconds:
                    problems.append("auth delay column holds no numeric value")
                elif not in_window:
                    problems.append("no logged auth delay falls inside [%.2f, %.2f]s" % (
                        ctx.delay_min, ctx.delay_max))
                else:
                    lines.append("%d/%d logged delays inside the window" % (len(in_window), len(seconds)))

            # connected_at / authenticated_at non empty
            for label, column in (("connected_at", connected_col), ("authenticated_at", authed_col)):
                if column is None:
                    continue
                values = _distinct_values(conn, connections_table, column, limit=200)
                non_empty = [v for v in values if not _looks_empty(v)]
                lines.append("%s column %r: %d/%d non-empty (sample=%s)" % (
                    label, column, len(non_empty), len(values),
                    _short(", ".join(str(v) for v in non_empty[:3]), 120)))
                if not non_empty:
                    problems.append("column %r (%s) is empty for every row" % (column, label))

        # ---------------- queries -----------------------------------------
        if queries_table:
            columns = _table_columns(conn, queries_table)
            lines.append("queries columns: %s" % columns)
            sql_col = _find_column(columns, (r"^sql", r"query", r"statement", r"^text", r"content", r"^command"))
            if sql_col is None:
                problems.append("queries has no SQL-text-like column")
            else:
                values = _distinct_values(conn, queries_table, sql_col, limit=500)
                normalized = {re.sub(r"\s+", " ", str(v)).strip().upper() for v in values if v is not None}
                lines.append("queries SQL column %r: %d distinct statements, sample=%s" % (
                    sql_col, len(normalized), _short("; ".join(list(normalized)[:5]), 240)))
                wanted = {"SHOW DATABASES", "SELECT 1"}
                found = {w for w in wanted if any(w in text for text in normalized)}
                missing = sorted(wanted - found)
                lines.append("expected keywords found: %s" % (sorted(found) or "none"))
                if missing:
                    problems.append("statements missing from the queries log: %s" % missing)
                if not ctx.used_sql:
                    lines.append("NOTE: no SQL was submitted by this run before the audit")
    finally:
        try:
            conn.close()
        except Exception:
            pass
    lines.extend(problems)
    return _result(FAIL if problems else PASS, lines)


# ==========================================================================
# Runner
# ==========================================================================
CHECKS = [
    ("pymysql accepts any credentials (3 pairs)", guarded(check_1_pymysql_any_credentials)),
    ("mysql.connector accepts any credentials", guarded(check_2_mysql_connector_any_credentials)),
    ("auth delay inside [min,max] and >= 1.8s", guarded(check_3_auth_delay)),
    ("SHOW DATABASES >= 5 rows incl. system schemas", guarded(check_4_show_databases)),
    ("SELECT 1 returns exactly 1", guarded(check_5_select_one)),
    ("SELECT VERSION()/USER()/DATABASE()", guarded(check_6_metadata_functions)),
    ("5+ statements on one connection, still usable", guarded(check_7_multi_statement_session)),
    ("malformed packets do not kill the server", guarded(check_8_malformed_packets)),
    ("concurrent connections all succeed", guarded(check_9_concurrency)),
    ("SQLite log audit (connections/queries)", guarded(check_10_sqlite_log_audit)),
]


def run_all(ctx, verbose=True):
    results = []
    for index, (title, func) in enumerate(CHECKS, start=1):
        if verbose:
            _emit("[run ] %2d/10 %s" % (index, title))
        started = time.perf_counter()
        try:
            outcome = func(ctx)
            if not isinstance(outcome, dict):
                raise TypeError("check returned %r instead of a dict" % type(outcome).__name__)
            status = outcome.get("status", FAIL)
            detail = outcome.get("detail", "")
        except Exception:
            status = FAIL
            detail = "uncaught exception:\n" + traceback.format_exc(limit=4).rstrip()
        elapsed = time.perf_counter() - started
        item = {"index": index, "name": title, "status": status, "detail": detail, "elapsed_s": round(elapsed, 4)}
        results.append(item)
        if verbose:
            _emit("[%-4s] %2d/10 %-44s %6.2fs" % (status, index, title, elapsed))
            for line in str(detail).splitlines():
                _emit("        " + line)
            _emit()
    return results


def print_summary(results):
    _emit("=" * 96)
    _emit("%-3s %-6s %-8s %s" % ("#", "STATUS", "TIME", "CHECK"))
    _emit("-" * 96)
    for item in results:
        _emit("%-3d %-6s %8.2fs %s" % (item["index"], item["status"], item["elapsed_s"], item["name"]))
    _emit("-" * 96)
    passed = sum(1 for item in results if item["status"] == PASS)
    failed = sum(1 for item in results if item["status"] == FAIL)
    skipped = sum(1 for item in results if item["status"] == SKIP)
    exit_code = 0 if failed == 0 else 1
    _emit("PASS=%d FAIL=%d SKIP=%d TOTAL=%d" % (passed, failed, skipped, len(results)))
    _emit("exit code: %d" % exit_code)
    _emit("=" * 96)
    return exit_code


def build_summary(results, ctx):
    failed = [item["name"] for item in results if item["status"] == FAIL]
    return {
        "target": "mysql://%s:%d" % (ctx.host, ctx.port),
        "db": os.path.abspath(ctx.db_path) if ctx.db_path else None,
        "delay_window": [ctx.delay_min, ctx.delay_max],
        "concurrency": ctx.concurrency,
        "checks": [
            {
                "index": item["index"],
                "name": item["name"],
                "status": item["status"],
                "detail": " | ".join(line.strip() for line in str(item["detail"]).splitlines() if line.strip()),
                "elapsed_s": item["elapsed_s"],
            }
            for item in results
        ],
        "passed": sum(1 for item in results if item["status"] == PASS),
        "failed": len(failed),
        "skipped": sum(1 for item in results if item["status"] == SKIP),
        "failed_checks": failed,
        "exit_code": 0 if not failed else 1,
    }


def build_parser():
    parser = argparse.ArgumentParser(
        prog="e2e_clients.py",
        description="End-to-end verification for a running MySQL honeypot "
                    "(pymysql + mysql.connector + raw MySQL 4.1 client + SQLite log audit).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1", help="honeypot host")
    parser.add_argument("--port", type=int, default=3306, help="honeypot MySQL port")
    parser.add_argument("--db", default="./honeypot.db", help="honeypot SQLite log; missing file -> SKIP")
    parser.add_argument("--delay-min", dest="delay_min", type=float, default=2.0,
                        help="minimum accepted authentication delay in seconds")
    parser.add_argument("--delay-max", dest="delay_max", type=float, default=6.0,
                        help="maximum accepted authentication delay in seconds")
    parser.add_argument("--concurrency", type=int, default=6, help="parallel connections for check 9")
    parser.add_argument("--skip-connector", dest="skip_connector", action="store_true",
                        help="skip the mysql.connector check")
    parser.add_argument("--json", action="store_true", help="print a single line of JSON instead of a report")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.delay_min > args.delay_max:
        parser.error("--delay-min must be <= --delay-max")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")

    ctx = Ctx(args)
    verbose = not args.json
    if verbose:
        _emit("target  : %s:%d" % (ctx.host, ctx.port))
        _emit("log db  : %s" % os.path.abspath(ctx.db_path))
        _emit("window  : auth delay in [%.2fs, %.2fs] (floor %.1fs)" % (ctx.delay_min, ctx.delay_max, MIN_DELAY_FLOOR))
        _emit("timeouts: connect %.0fs / io %.0fs" % (CONNECT_TIMEOUT, SOCKET_TIMEOUT))
        _emit("")
    try:
        results = run_all(ctx, verbose=verbose)
    except KeyboardInterrupt:
        _emit("interrupted")
        return 130
    if args.json:
        summary = build_summary(results, ctx)
        _emit(json.dumps(summary, ensure_ascii=False))
        return summary["exit_code"]
    return print_summary(results)


if __name__ == "__main__":
    sys.exit(main())
