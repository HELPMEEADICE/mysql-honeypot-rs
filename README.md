# mysql-honeypot-rs

A lightweight, low-memory **MySQL honeypot** written in Rust. It speaks the real
MySQL wire protocol (protocol version 10, 4.1+), accepts **any** username and
password, stalls every login by a random 2–6 seconds and records each session and
every submitted statement into a local SQLite database.

The point is to keep automation talking: scanners that only perform a handshake,
credential stuffers that try a thousand password pairs and exploit tools that run
`information_schema` queries should all believe they reached a genuine MySQL 8.0
server — while nothing they send is ever executed.

```
2026-11-06T01:47:53.928Z  INFO CONNECT id=1 peer=127.0.0.1:12829
2026-11-06T01:47:53.928Z  INFO HANDSHAKE id=1 version=8.0.36 plugin="caching_sha2_password"
2026-11-06T01:47:53.952Z  INFO AUTH id=1 username=root database= plugin="caching_sha2_password"
2026-11-06T01:47:56.145Z  INFO DELAY 2.192s id=1 delay_ms=2192
2026-11-06T01:47:56.146Z  INFO AUTH_OK id=1 username=root
2026-11-06T01:47:56.147Z  INFO QUERY id=1 kind="SELECT" sql=SELECT 1
2026-11-06T01:47:56.147Z  INFO DISCONNECT id=1 peer=127.0.0.1:12829 queries=2 duration_ms=2219
```

---

## 1. What it does and does not do

| Does | Does not |
| --- | --- |
| Listen on exactly one TCP port (default 3306) | Open an HTTP, WebSocket, metrics or admin port |
| Speak MySQL handshake, `COM_QUERY`, `COM_PING`, `COM_INIT_DB`, `COM_QUIT`, text result sets | Implement a SQL engine, storage engine or real credentials |
| Accept every login after a random delay | Connect to any MySQL server or outbound host |
| Answer `SHOW`, `SELECT`, `USE` and `information_schema` from an in-memory fake catalog | Execute `INSERT`/`UPDATE`/`DELETE`/`CREATE`/`DROP` — they are only acknowledged |
| Persist sessions and statements in SQLite (WAL) | Read host files, load local data, run commands, or proxy traffic |
| Enforce connection, packet, SQL-length, timeout and queue limits | Provide TLS, compression, or the binary (prepared statement) protocol |

---

## 2. Quick start

```bash
cargo run --release
# or, with an explicit configuration file
cargo run --release -- --config config.toml
# or the built binary
./target/release/mysql-honeypot-rs --config /etc/mysql-honeypot/config.toml
```

Then, from any machine that can reach the port:

```bash
mysql -h 127.0.0.1 -P 3306 -u root -pwrongpassword
mysql -h 127.0.0.1 -P 3306 -u admin -p123456
mysql -h 127.0.0.1 -P 3306 -u test  -panything
```

All three log in successfully after 2–6 seconds and land in a working fake
session:

```sql
mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| app_prod           |
| backup             |
+--------------------+
```

Python clients behave the same way:

```python
# PyMySQL
import pymysql
conn = pymysql.connect(host="127.0.0.1", port=3306, user="root", password="whatever")
with conn.cursor() as cur:
    cur.execute("SHOW DATABASES")
    print(cur.fetchall())

# mysql-connector-python
import mysql.connector
conn = mysql.connector.connect(host="127.0.0.1", port=3306, user="admin", password="123456")
cur = conn.cursor()
cur.execute("SELECT 1")
print(cur.fetchall())
```

Inspect the audit trail without stopping the honeypot:

```bash
python scripts/inspect_db.py ./honeypot.db
sqlite3 honeypot.db "SELECT id, source_ip, username, auth_delay_ms FROM connections ORDER BY id DESC LIMIT 10;"
```

---

## 3. Configuration

The honeypot reads a single TOML file (default `./config.toml`; override with
`--config <path>` or the `MYSQL_HONEYPOT_CONFIG` environment variable). A missing
file is not an error — built-in defaults are used and a warning is logged.

```toml
[server]
host = "0.0.0.0"                  # bind address (the only listener)
port = 3306                       # the only port this process opens
version = "8.0.36"                # advertised version (handshake, VERSION(), @@version)
max_connections = 256             # extra clients get ERR 1040 and are closed
idle_timeout_seconds = 300        # idle timeout for an authenticated session
handshake_timeout_seconds = 10    # deadline to finish the handshake
max_packet_size = 1048576         # largest logical MySQL payload accepted
max_sql_length = 16384            # bytes of each statement stored in SQLite
shutdown_grace_seconds = 5        # drain window on SIGTERM/SIGINT

[authentication]
always_accept = true              # the honeypot's whole point
delay_min_ms = 2000               # uniform random delay window, milliseconds
delay_max_ms = 6000

[database]
sqlite_path = "./honeypot.db"     # audit database
enable_wal = true                 # WAL journaling for concurrent readers
queue_capacity = 4096             # bounded log queue; overflow is counted, never blocks
busy_timeout_ms = 5000            # SQLITE_BUSY wait before giving up

[logging]
level = "info"                    # trace | debug | info | warn | error
log_queries = true                # one log line per statement (the DB always records them)
```

Every value is clamped into a usable range at startup (for example a
`delay_max_ms` below `delay_min_ms` is swapped, `max_connections = 0` becomes 1),
so a bad config file cannot produce a broken listener.

`always_accept = false` is a research aid: logins are then refused with
`ERROR 1045` after the same random delay, which is useful for measuring how
tools react to a "wrong password".

---

## 4. Deployment

### 4.1 Binary + systemd

```bash
sudo useradd --system --home-dir /var/lib/mysql-honeypot --shell /usr/sbin/nologin mysql-honeypot
sudo install -d -o mysql-honeypot -g mysql-honeypot /var/lib/mysql-honeypot /etc/mysql-honeypot
sudo install -m 0755 target/release/mysql-honeypot-rs /usr/local/bin/
sudo install -m 0640 -o root -g mysql-honeypot config.toml /etc/mysql-honeypot/config.toml
sudo install -m 0644 deploy/mysql-honeypot-rs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mysql-honeypot-rs
journalctl -u mysql-honeypot-rs -f
```

The unit is hardened (`ProtectSystem=strict`, empty capability set, syscall
filter, `ReadWritePaths` limited to the state directory). Port 3306 needs no
privileges, so the service runs unprivileged end to end.

`SIGTERM` stops the listener, tells live sessions to close, writes their
`disconnected_at`/`duration_ms` rows and flushes the log queue before exiting.

### 4.2 Docker / Compose

```bash
docker build -t mysql-honeypot-rs .
docker run -d --name mysql-honeypot \
  -p 3306:3306 \
  -v honeypot-data:/data \
  --read-only --tmpfs /tmp:size=8m \
  --cap-drop ALL --security-opt no-new-privileges \
  mysql-honeypot-rs:latest

# or
docker compose up -d --build
docker compose logs -f
```

The image runs as UID/GID `10001`, uses a read-only root filesystem, publishes
only TCP 3306, and keeps the SQLite database on the `honeypot-data` volume at
`/data/honeypot.db` (see `deploy/config.docker.toml`).

---

## 5. Protocol coverage

| Area | Implemented |
| --- | --- |
| Handshake | `HandshakeV10` (protocol 10), 20-byte scramble, capability split low/high, `caching_sha2_password` advertised |
| Handshake response | `HandshakeResponse41`: lenenc / secure-connection / NUL-terminated auth data, `CONNECT_WITH_DB`, `CLIENT_PLUGIN_AUTH`, `CLIENT_CONNECT_ATTRS` |
| Framing | 3-byte length + sequence id, `0xFFFFFF` continuation frames, length-encoded integers and strings |
| Packets | `OK`, `ERR` (with SQLSTATE), `EOF`, `AuthMoreData`, `AuthSwitchRequest`, `ColumnDefinition41`, text row |
| Result sets | Column count → column definitions → EOF → rows → EOF, and the `CLIENT_DEPRECATE_EOF` variant |
| Commands | `COM_QUERY`, `COM_PING`, `COM_INIT_DB`, `COM_QUIT`, `COM_STATISTICS`, `COM_PROCESS_INFO`, `COM_FIELD_LIST`, `COM_RESET_CONNECTION`, `COM_CHANGE_USER`, `COM_SET_OPTION`, `COM_DEBUG` |
| Refused cleanly | `COM_STMT_PREPARE` → `ERR 1295`, `COM_STMT_EXECUTE` → `ERR 1243`, unknown command → `ERR 1047` |

### 5.1 Authentication plugins

Authentication is **unconditional**: no credential is ever verified, and the
scrambled `auth_response` is parsed but discarded (never logged, never stored).

| Plugin requested by the client | Server response |
| --- | --- |
| `caching_sha2_password` (default, MySQL 8.x) | `AuthMoreData` with the `0x03` fast-auth-success marker, then `OK` |
| `mysql_native_password` | `OK` directly |
| `sha256_password`, `mysql_clear_password`, anything unknown | `OK` directly (the protocol's terminal success state) |
| No plugin name (`CLIENT_PLUGIN_AUTH` unset) | `OK` directly |

Only the fast path of `caching_sha2_password` is used, deliberately: the
`0x04` full-authentication path would require RSA key exchange or TLS, and the
honeypot offers neither.

`CLIENT_SSL` is **not** advertised. A client that sends an `SSLRequest` anyway
receives `ERR 1043` instead of a hang or a fake "encrypted" session.

---

## 6. The fake database

All catalog content lives in memory and is generated at startup.

* Schemas: `information_schema`, `mysql`, `performance_schema`, `sys`,
  `app_prod`, `backup`.
* `app_prod`: `users`, `orders`, `sessions`, `products` with plausible rows
  (real-looking password hashes, timestamps, amounts).
* `backup`: `users_backup`, `orders_2024`.
* `mysql`: `user`, `db`, `tables_priv`, `columns_priv`, `proc`, `func`.
* `information_schema`: `SCHEMATA`, `TABLES`, `COLUMNS`, `STATISTICS`,
  `ENGINES`, `PROCESSLIST`, `USER_PRIVILEGES`, `CHARACTER_SETS`,
  `KEY_COLUMN_USAGE`, `VIEWS` — populated from the catalog above, so
  `SELECT table_name FROM information_schema.tables WHERE table_schema = 'app_prod'`
  returns exactly that schema's tables.

Supported statements include `SELECT` (scalar expressions, arithmetic literals,
system variables, functions such as `VERSION()`/`USER()`/`DATABASE()`/
`CONNECTION_ID()`/`NOW()`, table projections, `COUNT(*)`, `LIMIT`), `SHOW`
(`DATABASES`, `TABLES`, `COLUMNS`, `CREATE TABLE`, `VARIABLES`, `STATUS`,
`PROCESSLIST`, `GRANTS`, `INDEX`, `ENGINES`, `CHARACTER SET`, `COLLATION`,
`PRIVILEGES`, `TABLE STATUS`, `WARNINGS`), `USE`, `DESCRIBE`, `EXPLAIN`, `SET`,
transactions, and every DML/DDL keyword — which is acknowledged with an OK packet
and nothing else.

A literal `WHERE` clause is used as a coarse row filter so schema-scoped
`information_schema` probes look right. `LOAD DATA` is answered with
`ERR 1148`, and unknown statements get a realistic `ERR 1064` syntax error; the
session stays open in both cases.

---

## 7. Log database

SQLite, WAL mode, parameterized statements, written by a dedicated thread from a
bounded queue. Timestamps are UTC in `YYYY-MM-DDTHH:MM:SS.mmmZ`.

```
honeypot.db
├── connections
│   ├── id                  INTEGER PRIMARY KEY   -- monotonic, continues across restarts
│   ├── source_ip           TEXT                  -- IPv4 or IPv6
│   ├── source_port         INTEGER
│   ├── username            TEXT                  -- NULL if the handshake never finished
│   ├── connected_at        TEXT
│   ├── authenticated_at    TEXT
│   ├── auth_delay_ms       INTEGER               -- the delay actually applied
│   ├── disconnected_at     TEXT
│   ├── duration_ms         INTEGER
│   ├── client_capabilities INTEGER               -- raw handshake capability flags
│   └── client_version_info TEXT                  -- _client_name=..., _os=...
└── queries
    ├── id            INTEGER PRIMARY KEY
    ├── connection_id INTEGER                      -- connections.id
    ├── source_ip     TEXT
    ├── username      TEXT
    ├── sql_text      TEXT                         -- clipped to max_sql_length
    ├── query_type    TEXT                         -- SELECT/INSERT/SHOW/USE/PREPARE/...
    ├── executed_at   TEXT
    └── response_type TEXT                         -- RESULTSET(cols=1,rows=1), OK(affected=1), ERR(1064)
```

Indexes cover `connections(source_ip)`, `connections(connected_at)`,
`queries(connection_id)`, `queries(source_ip)`, `queries(query_type)` and
`queries(executed_at)`.

Useful queries:

```sql
-- noisiest sources
SELECT source_ip, COUNT(*) AS sessions FROM connections GROUP BY source_ip ORDER BY sessions DESC LIMIT 20;

-- credential pairs attempted
SELECT username, COUNT(*) FROM connections GROUP BY username ORDER BY 2 DESC;

-- what the scanners actually ran
SELECT query_type, COUNT(*) FROM queries GROUP BY query_type ORDER BY 2 DESC;

-- full timeline for one attacker
SELECT c.id, c.source_ip, q.executed_at, q.sql_text
FROM connections c JOIN queries q ON q.connection_id = c.id
WHERE c.source_ip = '198.51.100.24' ORDER BY q.id;
```

Because `id` keeps growing across restarts, a restarted honeypot never overwrites
earlier rows.

---

## 8. Resource limits and failure behaviour

* `max_connections` slots are held by a semaphore; a client over the limit gets a
  real `ERR 1040 (Too many connections)` before any handshake and is closed.
* `max_packet_size` caps a logical payload (continuation frames included) before
  the bytes are buffered; oversize declarations are rejected without allocating.
* `max_sql_length` clips stored statements on a UTF-8 boundary; the client still
  receives a normal response.
* `handshake_timeout_seconds` and `idle_timeout_seconds` bound every wait.
* The log queue is bounded: when the disk cannot keep up, events are dropped and
  counted (`log queue full — dropping events`) instead of blocking sessions.
* SQLite failures (busy, disk full, corrupt handle) are retried once against a
  freshly opened connection; a batch that still fails is counted in `failed`
  rather than retried forever.
* Malformed input never panics: every decoder is bounds-checked, and a session
  that misbehaves is closed while the process keeps serving.
* The runtime is multi-threaded and every network wait is `async`, so one
  client's 2–6 second delay never delays another.

---

## 9. Testing and verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

* `src/**` — unit tests for framing, length-encoded integers, handshake build and
  parse, OK/ERR/EOF/result-set encoders, config clamping, statement routing,
  catalog construction, delay sampling and the SQLite writer.
* `tests/integration.rs` — a real TCP client against a real listener on an
  ephemeral port: arbitrary credentials, the 2–6 s window (with defaults),
  `SHOW DATABASES`, `SELECT 1`, long statement streams, malformed and truncated
  packets, unknown commands, concurrency, the connection limit, the
  `DEPRECATE_EOF` and `mysql_native_password` paths, `COM_PING`/`COM_INIT_DB`/
  `COM_QUIT`, SQL truncation, and log persistence across a restart.
* `scripts/e2e_clients.py` — end-to-end verification with **PyMySQL** and
  **mysql-connector-python** plus a hand-written raw-protocol client:
  10 checks covering login, delay timing, result sets, statement persistence,
  malformed packets and concurrency, and finally auditing `honeypot.db`.
  `python scripts/inspect_db.py` prints a read-only summary of a log database.

Measured on the reference run (release build, Windows host, loopback):

```
PASS  pymysql accepts any credentials (3 pairs)
PASS  mysql.connector accepts any credentials
PASS  auth delay inside [min,max] and >= 1.8s            2.97s (one probing login)
PASS  SHOW DATABASES >= 5 rows incl. system schemas      rows=6
PASS  SELECT 1 returns exactly 1                         row=(1,)
PASS  SELECT VERSION()/USER()/DATABASE()                 8.0.36 / root@% / None
PASS  5+ statements on one connection, still usable
PASS  malformed packets do not kill the server
PASS  concurrent connections all succeed                 5.81s vs 28.37s serial estimate
PASS  SQLite log audit                                   both tables, every SQL, all delays in window
PASS=10 FAIL=0
```

Observed authentication delays across runs: `2034, 2192, 2965, 3121, 3351, 3755,
3776, 3820, 4615, 5488, 5748, 5944` ms — 23/23 logged delays inside the
configured window, minimum 2.03 s, maximum 5.94 s. Loopback IPv6 (`::1`) was
verified separately: the listener binds `::1`, the client connects, and
`source_ip` is stored as `::1`.

---

## 10. Known limitations

* **No TLS.** `CLIENT_SSL` is not advertised and an `SSLRequest` is refused. A
  client configured with `--ssl-mode=REQUIRED` will not connect — by design, so
  no client can believe it has an encrypted channel.
* **No binary protocol.** `COM_STMT_PREPARE` returns `ERR 1295`, so clients that
  insist on server-side prepared statements (some JDBC configurations, some ORMs)
  will see an error. The statement text is still logged as `PREPARE`. Text-protocol
  clients — the `mysql` CLI, PyMySQL, `mysql.connector`'s default cursor, most
  scanners — are unaffected.
* **One statement per `COM_QUERY`.** `CLIENT_MULTI_STATEMENTS` is not advertised;
  extra statements in one payload are logged but only the first is answered.
* **No `LOAD DATA LOCAL`, no compression.** Both capability flags stay off, so
  the honeypot can never be turned into a file transport.
* **Static catalog.** Row counts in `information_schema` do not change in response
  to DDL; a successful `CREATE TABLE` is not reflected in later `SHOW TABLES`.
  This is intentional: nothing a client sends mutates the honeypot's state.
* **Connection ids on the wire are 32-bit**, so after 2^32 sessions the value
  reported by `CONNECTION_ID()` wraps while `connections.id` keeps growing.
* **The `mysql` CLI was not available in the build environment** used for the
  reference run. Its protocol requirements (text result sets, `DEPRECATE_EOF`,
  `caching_sha2_password`) are covered by the raw-protocol integration client and
  by PyMySQL/`mysql.connector`, but the CLI binary itself was not executed here.

---

## 11. Legality and intent

This is a defensive deception system: it accepts connections, never
authenticates anyone against a real service, never forwards traffic and never
executes anything a client sends. Deploy it only on hosts and ports you are
authorised to monitor, and treat the captured SQL as untrusted data — it is
attacker-supplied text.

## 12. License

Copyright (C) 2026 HELPMEEADICE.

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU General Public License as published by the Free Software
Foundation, version 3** of the License (SPDX: `GPL-3.0-only`).

This program is distributed in the hope that it will be useful, but **WITHOUT ANY
WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

The full license text is in [`LICENSE`](LICENSE). Every source file carries an
`SPDX-License-Identifier: GPL-3.0-only` tag; the repository is
<https://github.com/HELPMEEADICE/mysql-honeypot-rs>.

If you prefer to redistribute under "version 3 or any later version", the FSF
recommends that form; this project ships the strict `version 3` grant, so
relicensing to `GPL-3.0-or-later` requires the copyright holder's consent.
