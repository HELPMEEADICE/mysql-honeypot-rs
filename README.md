# mysql-honeypot-rs

A lightweight **MySQL honeypot** written in Rust. It speaks the real MySQL wire
protocol (protocol version 10, 4.1+), accepts **any** username and password,
stalls every login by a random 2–6 seconds and records each session and every
submitted statement into a local SQLite database.

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
retention_days = 0                # 0 = keep every row (the conservative default)
max_size_bytes = 0                # 0 = no size cap; otherwise trim the oldest rows at startup

[logging]
level = "info"                    # trace | debug | info | warn | error
log_queries = true                # one log line per statement (the DB always records them)

[virtualdb]
enabled = true                    # simulate writes against a per-session overlay
max_tables = 32                   # tables one session may create
max_rows_per_table = 1000         # rows one virtual table may hold
max_total_rows = 2000             # rows across the whole overlay
max_string_bytes = 1024           # bytes in one stored string value
max_total_bytes = 65536           # bytes of overlay storage per session (64 KiB)
```

Every value is clamped into a usable range at startup (for example a
`delay_max_ms` below `delay_min_ms` is swapped, `max_connections = 0` becomes 1),
so a bad config file cannot produce a broken listener.

`always_accept = false` is a research aid: logins are then refused with
`ERROR 1045` after the same random delay, which is useful for measuring how
tools react to a "wrong password".

`[virtualdb]` bounds the stateful simulation described in section 6. Setting
`enabled = false` makes every write a bare `OK` with no stored state at all,
which is the cheapest possible profile; the budgets are what stop a
`CREATE TABLE` / `INSERT` loop from growing the process, so lowering them is the
right move on a memory-constrained host.

---

## 4. Deployment

`deploy/` holds the deployment artefacts: the hardened systemd unit, the
container configuration, and [`deploy/README.md`](deploy/README.md), which
documents the config schema, every limit these files set and the reasoning
behind them.

### 4.1 Binary + systemd

```bash
sudo useradd --system --home-dir /var/lib/mysql-honeypot --shell /usr/sbin/nologin mysql-honeypot
sudo install -d -m 0750 -o mysql-honeypot -g mysql-honeypot /var/lib/mysql-honeypot
sudo install -d -m 0755 /etc/mysql-honeypot
sudo install -m 0755 target/release/mysql-honeypot-rs /usr/local/bin/
sudo install -m 0640 -o root -g mysql-honeypot config.toml /etc/mysql-honeypot/config.toml
sudo install -m 0644 deploy/mysql-honeypot-rs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mysql-honeypot-rs
journalctl -u mysql-honeypot-rs -f
```

The unit is hardened (`ProtectSystem=strict`, `ProtectProc=invisible`,
`ProcSubset=pid`, `ProtectClock`/`ProtectHostname`/`ProtectKernelLogs`, an empty
capability set, a `@system-service` syscall filter, and `ReadWritePaths` limited
to the state directory). Everything it creates is owner-only (`UMask=0077`).
Port 3306 needs no privileges, so the service runs unprivileged end to end.

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
  --memory 128m --memory-swap 128m --pids-limit 256 --oom-score-adj 500 \
  --ulimit nofile=4096:8192 \
  mysql-honeypot-rs:latest

# or
docker compose up -d --build
docker compose logs -f
```

The image runs as UID/GID `10001`, uses a read-only root filesystem, publishes
only TCP 3306, and keeps the SQLite database on the `honeypot-data` volume at
`/data/honeypot.db` (see `deploy/config.docker.toml`).

`docker-compose.yml` pins every limit explicitly — `mem_limit` and
`memswap_limit` both `128m` (so swap is off), `oom_score_adj: 500` (the decoy is
reclaimed before real workloads), `pids_limit: 256`, `ulimits.nofile`
`4096:8192`, `cap_drop: ALL`, `no-new-privileges`, bounded `json-file` logging
and `stop_grace_period: 20s` — twice the 10 s drain window that
`deploy/config.docker.toml` asks for, so SIGTERM always finishes before Docker
escalates to SIGKILL.

The image ships no `HEALTHCHECK` on purpose: the process speaks only the MySQL
protocol and `debian:bookworm-slim` carries no client able to probe it (`sh` is
`dash`, without `/dev/tcp`), so a probe would be a check that never passes. Use
an operator-side TCP check against port 3306 instead.

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
| Prepared statements | `COM_STMT_PREPARE` (metadata: parameter and column definitions), `COM_STMT_EXECUTE` (binary result sets), `COM_STMT_CLOSE`, `COM_STMT_RESET`, `COM_STMT_SEND_LONG_DATA` |
| Refused cleanly | `COM_STMT_FETCH` (no cursors) → `ERR 1295`, unknown statement handle → `ERR 1243`, unknown command → `ERR 1047` |

`COM_CHANGE_USER` is handled as a real identity switch: the new login name and
database are adopted, the session's virtual database is reset exactly as MySQL
resets it, an `OK` packet confirms the switch, and both the `connections` row and
a `CHANGE_USER` audit entry record it.

Prepared statements answer with the binary row format (`0x00` header, NULL
bitmap, then typed values). Numeric columns are re-typed from the actual page, so
`SELECT COUNT(*)` through `COM_STMT_EXECUTE` returns an integer, not a string.

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

`SELECT` is answered by a small expression engine, not by pattern matching:

* **Projections** — `*`, `table.*`, bare columns and scalar expressions, with
  optional `AS` aliases. Up to 400 columns per result set.
* **`WHERE`** — a column-aware parser for `=`, `!=`, `<>`, `>`, `>=`, `<`, `<=`,
  `AND`, `OR`, `NOT`, `IN`, `LIKE`, `IS [NOT] NULL` and parentheses, with MySQL
  comparison semantics: a number on either side compares numerically, two
  strings compare case-insensitively, and `NULL` never matches. `LIKE` uses the
  linear backtracking matcher, so a pathological pattern cannot blow up.
* **Aggregates** — `COUNT(*)`, `COUNT(col)`, `COUNT(DISTINCT col)`, `MIN`,
  `MAX`, `SUM`, `AVG`, optionally with `GROUP BY`. An aggregate always returns
  exactly one row per group (empty table → `0` for `COUNT`, `NULL` otherwise) and
  is never truncated by the row cap.
* **Pagination** — `ORDER BY expr [ASC|DESC], ...`, `LIMIT n`, `LIMIT o, n` and
  `LIMIT n OFFSET o`, applied in MySQL's order (filter → sort → offset → take).
  Absurd integers saturate instead of overflowing.
* **Functions** — `VERSION`, `DATABASE`, `USER`, `CURRENT_USER`, `CONNECTION_ID`,
  `NOW`/`CURDATE`/`CURTIME`/`UNIX_TIMESTAMP`, `LAST_INSERT_ID`, `ROW_COUNT`,
  `MD5`, `SHA`/`SHA1`, `SHA2` (224/256/384/512), `PASSWORD` (the MySQL 5.7
  `*`+`SHA1(SHA1(x))` form), `LENGTH`, `CHAR_LENGTH`, `UPPER`/`LOWER`, `HEX`,
  `ASCII`, `CONCAT`, `TRIM`, `REPLACE`, `SUBSTRING`, `LEFT`/`RIGHT`, `ABS`,
  `ROUND`, `CEIL`, `FLOOR`, `IFNULL`, `COALESCE`, `IF`, `NULLIF`, `CAST`,
  `SLEEP` and more. The digests are genuinely computed, so a client comparing
  `MD5('x')` against its own result gets the same answer; `SLEEP()` returns `0`
  immediately and never blocks a session.

`CURRENT_USER()` reports the account matched by the login (`<user>@%`, which is
exactly what the fake `mysql.user` table lists), `USER()` reports
`<user>@<peer address>`, and `SHOW GRANTS` names the same account — so the
identity view never contradicts itself.

An expression the grammar does not cover (`BETWEEN`, `XOR`, subqueries,
`CASE`) makes the answer *narrower*, never wider: the result set comes back empty
and is tagged `degraded` in `queries.response_type`. Referring to a column that
does not exist is the real `ERR 1054`; an unknown function is `ERR 1305`.

`SHOW` (`DATABASES`, `TABLES`, `COLUMNS`, `CREATE TABLE`, `VARIABLES`, `STATUS`,
`PROCESSLIST`, `GRANTS`, `INDEX`, `ENGINES`, `CHARACTER SET`, `COLLATION`,
`PRIVILEGES`, `TABLE STATUS`, `WARNINGS`), `USE`, `DESCRIBE`, `EXPLAIN`, `SET`
(including `SET @var = ...`) and transactions are supported as before.

`LOAD DATA` is answered with `ERR 1148`, and unknown statements get a realistic
`ERR 1064` syntax error; the session stays open in both cases.

### 6.1 Stateful, session-private simulation

`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE` and `CREATE`/`DROP TABLE`/`DATABASE`
really do change a virtual database — but only the caller's copy of it:

```
session A: INSERT INTO users VALUES (9001,'mallory')   -> OK, affected=1
session A: SELECT * FROM users WHERE id = 9001        -> 1 row
session B: SELECT * FROM users WHERE id = 9001        -> 0 rows
session A: DROP TABLE users                           -> OK
session A: SELECT * FROM users                        -> ERR 1146
session B: SELECT * FROM users                        -> still 3 rows
```

The implementation is copy-on-write: a session that never writes allocates
nothing, and the first write to a table clones exactly that table into a
per-session overlay. `LAST_INSERT_ID()`, `ROW_COUNT()` and the affected-row
count of every statement stay consistent with what actually happened, and
`information_schema` (plus `SHOW TABLES` / `SHOW TABLE STATUS` / `SHOW CREATE
TABLE`) is regenerated from the base catalog plus the overlay, so a table you
just created really is listed.

Nothing here touches a real database, the filesystem or the network: it is a
bounded in-memory map of `String`s behind the budgets in `[virtualdb]`. Exceeding
a budget produces the MySQL error a real server would produce (`ER_TOO_MANY_TABLES`,
`ER_RECORD_FILE_FULL`, `ER_DATA_TOO_LONG`) rather than growing without limit.

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

Three reliability properties are enforced by the writer:

* **Lifecycle events survive a query flood.** A saturated queue drops `Query`
  events (that is what the bound is for) but parks `CONNECT` / `IDENTIFIED` /
  `AUTH_OK` / `DISCONNECT` in a small overflow buffer, because a lost connect row
  would orphan every later statement from that session.
* **Every row stands on its own.** Each write is an upsert keyed on the
  connection id, so an identity or a query that arrives without its `CONNECT`
  still produces a complete, attributable row instead of a lost `UPDATE`.
* **The counters are honest.** `enqueued + dropped` is every call to `record()`,
  and `written + failed` is every event the writer handled; a statement that
  fails inside a batch is counted in `failed` instead of being absorbed into a
  successful commit. The final tallies are logged when the process stops.

`retention_days` and `max_size_bytes` are **off by default**: deleting forensic
evidence should be an explicit decision. When `retention_days > 0`, rows older
than that window are removed at startup; when `max_size_bytes > 0`, the oldest
query rows are trimmed and the file compacted until it fits. Both operations run
once, on the writer thread, before any session is accepted.

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
* The log queue is bounded: when the disk cannot keep up, query events are
  dropped and counted (`log queue full — dropping query events`) instead of
  blocking sessions, while lifecycle events use their own overflow buffer.
* Refusal replies are bounded too: once 32 `ERR 1040` responses are in flight, a
  further over-limit socket is closed immediately instead of spawning a task. A
  connection flood therefore cannot turn into an unbounded task flood.
* Every SQL budget is explicit: 200 result rows, 400 projected columns, 512 KiB
  of result bytes, 2 048 tokens per statement, 24 levels of expression nesting and
  512 parser steps. Exceeding the column or row budget is reported the way MySQL
  reports it (or silently paginated), never by allocating first.
* The virtual database is bounded by `[virtualdb]` (table count, rows per table,
  total rows, string length and total bytes per session).
* `SLEEP()` and `BENCHMARK()` return immediately, so neither can be used to hold
  a connection slot with server-side work.
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
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

* `src/**` — unit tests for framing, length-encoded integers, handshake build and
  parse, OK/ERR/EOF/result-set encoders, config clamping, statement routing,
  catalog construction, delay sampling and the SQLite writer.
* `tests/integration.rs` — a real TCP client against a real listener on an
  ephemeral port: arbitrary credentials, the configured delay window,
  `SHOW DATABASES`, `SELECT 1`, long statement streams, malformed and truncated
  packets, unknown commands, concurrency, the connection limit, the
  `DEPRECATE_EOF` and `mysql_native_password` paths, `COM_PING`/`COM_INIT_DB`/
  `COM_QUIT`, SQL truncation, log persistence across a restart, the handshake
  timeout, and — for the SQL engine — `COUNT(*)`/`WHERE`/`LIMIT`/`ORDER BY`
  semantics, session isolation of the virtual database, prepared statements over
  the binary protocol, `COM_CHANGE_USER` and the logger's counters.
* `fuzz/` — a `cargo-fuzz` crate with four targets (`packet`, `handshake`,
  `config`, `framing`). It is a separate workspace, so `cargo build`/`test`/
  `clippy` at the repository root are unaffected; run it with
  `cargo +nightly fuzz run <target>`. See [`fuzz/README.md`](fuzz/README.md).
* `scripts/bench.py` — a reproducible measurement harness for a *release* build.
  It starts the binary on an ephemeral port with a temporary configuration and
  reports idle RSS, RSS at 100 and 256 concurrent authenticated sessions, the
  login-delay distribution, query throughput (single connection and 32 workers),
  SQLite row-write throughput, database size, and behaviour under malformed
  packets, a connection burst and abrupt disconnects. It speaks the protocol
  directly, so it needs no driver:

  ```bash
  cargo build --release --locked
  python scripts/bench.py            # full run
  python scripts/bench.py --quick    # 100 sessions instead of 100 + 256
  python scripts/bench.py --json     # machine-readable summary
  ```

  Every figure it prints is produced by that run on that machine, which is why
  no measurement is stored in this repository.
* `scripts/e2e_clients.py` — end-to-end verification of a *running* honeypot with
  **PyMySQL** and **mysql-connector-python** plus a hand-written raw-protocol
  client: 10 checks covering login, delay timing, result sets, statement
  persistence, malformed packets and concurrency, and finally a read-only audit
  of `honeypot.db`. It prints one PASS/FAIL/SKIP line per check, emits a single
  JSON line with `--json`, and exits non-zero if any check fails;
  [`scripts/README-e2e.md`](scripts/README-e2e.md) lists every check and flag.
  `python scripts/inspect_db.py` prints a read-only summary of a log database.

Every value that script prints belongs to the run that produced it — delays, row
counts and timings are observations, not constants, and none of them is stored in
this repository.

The delay window itself is enforced by construction: the bounds are clamped at
startup (an inverted pair is swapped, a zero minimum becomes 1 ms), so a client
always waits inside `[delay_min_ms, delay_max_ms]`. `server.host` accepts any IPv4
or IPv6 literal — `::1` and `[::1]` are both valid, the brackets are stripped — so
an IPv6-only listener is a one-line config change.

---

### 9.1 CI and release builds

Two GitHub Actions workflows live in `.github/workflows/`:

**`ci.yml`** runs on every push to `main`, every pull request and on demand:

| Job | What it proves |
| --- | --- |
| `rustfmt` | `cargo fmt --all -- --check` |
| `clippy` | `cargo clippy --all-targets --locked -- -D warnings` |
| `test` (ubuntu / windows / macos) | `cargo test --locked` (unit, integration and doc tests) and `cargo build --release --locked` |
| `package` | `cargo package` still produces a crate archive containing `LICENSE`, `README.md`, `src/main.rs`, `src/lib.rs` |

`-D warnings` is passed after `--` so it applies to this crate only; third-party
crates are never built with it.

**`build.yml`** produces release binaries for nine targets and can be started in
two ways:

```bash
# 1) publish a GitHub release — assets are attached to it automatically
gh release create v0.1.0 --title "v0.1.0" --notes "first release"
# 2) or run it manually — archives appear under the run's "Artifacts" section
gh workflow run build.yml --ref main
```

`workflow_dispatch` accepts an optional comma-separated `targets` input (matrix
names such as `linux-mips,windows-aarch64`) to build a subset instead of all
nine targets.

| Target triple | Runner | Toolchain |
| --- | --- | --- |
| `x86_64-pc-windows-msvc` | windows-latest | stable, MSVC x64 dev shell |
| `aarch64-pc-windows-msvc` | windows-latest | stable, MSVC arm64 dev shell |
| `x86_64-apple-darwin` | macos-latest | stable |
| `aarch64-apple-darwin` | macos-latest | stable |
| `x86_64-unknown-linux-gnu` | ubuntu-latest | stable |
| `aarch64-unknown-linux-gnu` | ubuntu-latest | stable + `cross` |
| `armv7-unknown-linux-gnueabihf` | ubuntu-latest | stable + `cross` |
| `riscv64gc-unknown-linux-gnu` | ubuntu-latest | stable + `cross` |
| `mips-unknown-linux-gnu` | ubuntu-24.04 | nightly + `-Z build-std` (Tier 3: no prebuilt std) |

Each job publishes `mysql-honeypot-rs-<version>-<triple>.tar.gz` containing the
binary, `LICENSE`, `README.md` and `config.toml`, plus a matching `.sha256`.

The release profile used by those builds is deliberately maximal:

```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "debuginfo"
debug = false
incremental = false
overflow-checks = false
```

Note the consequence of `panic = "abort"`: a panic anywhere terminates the whole
process rather than unwinding a single session task. The parser and the session
state machine are written and tested to be panic-free on hostile input
(`random_garbage_never_kills_the_server`), but if you prefer per-session
isolation at the cost of a slightly larger binary, switch that line back to the
default `unwind`.

---

## 10. Known limitations

* **No TLS.** `CLIENT_SSL` is not advertised and an `SSLRequest` is refused. A
  client configured with `--ssl-mode=REQUIRED` will not connect — by design, so
  no client can believe it has an encrypted channel.
* **Prepared statements ignore their parameters.** The binary protocol is
  implemented end to end, but placeholder values are treated as `NULL`: a
  `SELECT ... WHERE name = ?` returns no rows and the statement is logged as
  `PREPARE`. The point is protocol compatibility, not result fidelity.
* **Cursors are not implemented.** `COM_STMT_FETCH` answers `ERR 1295`.
* **One statement per `COM_QUERY`.** `CLIENT_MULTI_STATEMENTS` is not advertised;
  extra statements in one payload are logged but only the first is answered.
* **No `LOAD DATA LOCAL`, no compression.** Both capability flags stay off, so
  the honeypot can never be turned into a file transport.
* **Unmodelled SQL degrades to an empty result.** `BETWEEN`, `XOR`, subqueries,
  `CASE`, `JOIN`, `UNION`, `HAVING` and `GROUP BY` over expressions the parser
  cannot fold produce fewer rows than a real server would, never more. The
  response is tagged `degraded` so the audit trail shows it.
* **`SELECT ... FROM <table>` works without a database selected.** A real server
  answers `ERR 1046`; the honeypot searches every schema so a scanner that skips
  `USE` still sees the decoy tables. `SHOW TABLES` does require a schema, exactly
  like MySQL.
* **MySQL error codes are approximated.** `ER_BAD_FIELD_ERROR`, `ER_NO_SUCH_TABLE`,
  `ER_BAD_DB_ERROR`, `ER_DATA_TOO_LONG`, `ER_RECORD_FILE_FULL` and
  `ER_UNKNOWN_STMT_HANDLER` carry the real code, SQLSTATE and message shape, but
  the wording is not byte-identical to a specific 8.0 point release.
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
