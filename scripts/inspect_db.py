#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only summary of a mysql-honeypot-rs SQLite log database.

Usage:
    python scripts/inspect_db.py [path/to/honeypot.db] [--limit N]

Prints schema, row counts, the most recent sessions and statements, and the
observed authentication-delay distribution. It never writes to the database.
"""

from __future__ import annotations

import argparse
import statistics
import sqlite3
import sys
from pathlib import Path


def table_names(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    return [row[0] for row in rows]


def columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", nargs="?", default="honeypot.db")
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()

    path = Path(args.database)
    if not path.exists():
        print(f"no such database: {path}", file=sys.stderr)
        return 1

    # Read-only so an operator can inspect a live honeypot safely.
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row

    journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
    print(f"database      : {path.resolve()}")
    print(f"journal_mode  : {journal}")
    print(f"tables        : {', '.join(table_names(connection))}")
    for table in table_names(connection):
        print(f"  {table} columns: {', '.join(columns(connection, table))}")

    sessions = connection.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
    statements = connection.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
    print(f"\nconnections   : {sessions}")
    print(f"queries       : {statements}")

    print(f"\nlatest {args.limit} sessions")
    print("  id   source                       user           delay   queries  connected_at")
    for row in connection.execute(
        """
        SELECT c.id, c.source_ip, c.source_port, c.username, c.auth_delay_ms,
               c.connected_at,
               (SELECT COUNT(*) FROM queries q WHERE q.connection_id = c.id) AS n
        FROM connections c
        ORDER BY c.id DESC
        LIMIT ?
        """,
        (args.limit,),
    ):
        user = row["username"] if row["username"] is not None else "-"
        delay = f"{row['auth_delay_ms']}ms" if row["auth_delay_ms"] else "-"
        print(
            f"  {row['id']:<4} {row['source_ip'] + ':' + str(row['source_port']):<28} "
            f"{user:<14} {delay:<7} {row['n']:<7} {row['connected_at']}"
        )

    print(f"\nlatest {args.limit} statements")
    print("  id     conn  type       response                  sql")
    for row in connection.execute(
        """
        SELECT id, connection_id, query_type, response_type, sql_text
        FROM queries ORDER BY id DESC LIMIT ?
        """,
        (args.limit,),
    ):
        sql = " ".join(str(row["sql_text"]).split())
        if len(sql) > 70:
            sql = sql[:67] + "..."
        print(
            f"  {row['id']:<6} {row['connection_id']:<5} {row['query_type']:<10} "
            f"{row['response_type']:<25} {sql}"
        )

    kinds = connection.execute(
        "SELECT query_type, COUNT(*) FROM queries GROUP BY query_type ORDER BY 2 DESC"
    ).fetchall()
    if kinds:
        print("\nstatement mix")
        for kind, count in kinds:
            print(f"  {kind:<12} {count}")

    delays = [
        row[0]
        for row in connection.execute(
            "SELECT auth_delay_ms FROM connections WHERE auth_delay_ms IS NOT NULL"
        )
    ]
    if delays:
        print(
            f"\nauth delay    : n={len(delays)} min={min(delays)}ms "
            f"median={int(statistics.median(delays))}ms max={max(delays)}ms"
        )

    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
