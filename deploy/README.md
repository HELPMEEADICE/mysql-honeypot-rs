# Deployment files

Everything in this directory is a deployment artefact for
[`mysql-honeypot-rs`](../README.md). The binary itself is built from `src/`
(see the [main README](../README.md)); this file documents how the artefacts
here are meant to be used and what each setting does.

| File | Used by |
| --- | --- |
| [`mysql-honeypot-rs.service`](mysql-honeypot-rs.service) | systemd, for a plain binary install |
| [`config.docker.toml`](config.docker.toml) | the container image (`/etc/mysql-honeypot/config.toml`) |
| [`../Dockerfile`](../Dockerfile) / [`../docker-compose.yml`](../docker-compose.yml) | `docker build`, `docker compose up` |

The project lives at <https://github.com/HELPMEEADICE/mysql-honeypot-rs> and is
licensed `GPL-3.0-only` ([full text](../LICENSE)).

---

## 1. Configuration schema

The honeypot reads one TOML file. Every struct in `src/config.rs` is annotated
`#[serde(deny_unknown_fields)]`, so **an unknown key is a hard startup error**,
not a warning: whenever a key is added, renamed or removed in `src/config.rs`,
the deployment config here has to follow in the same change. A *missing* file is
not an error — built-in defaults are used and a warning is logged.

`config.docker.toml` is intentionally a subset of the schema: it only overrides
what a container needs (the bind address and the volume path) and inherits every
other default.

| Key | Type | Default | Accepted range (clamped at startup) |
| --- | --- | --- | --- |
| `server.host` | string | `0.0.0.0` | any address; empty falls back to the default, `[::1]` is normalised to `::1` |
| `server.port` | integer | `3306` | 0–65535 (`u16`) |
| `server.version` | string | `8.0.36` | any non-empty string |
| `server.max_connections` | integer | `256` | 1–65535 |
| `server.idle_timeout_seconds` | integer | `300` | 5–86400 |
| `server.handshake_timeout_seconds` | integer | `10` | 1–300 |
| `server.max_packet_size` | integer | `1048576` | 4096–67108864 |
| `server.max_sql_length` | integer | `16384` | 64–1048576 |
| `server.shutdown_grace_seconds` | integer | `5` | 0–120 |
| `authentication.always_accept` | boolean | `true` | — |
| `authentication.delay_min_ms` | integer | `2000` | ≥ 1; swapped with `delay_max_ms` if inverted |
| `authentication.delay_max_ms` | integer | `6000` | ≥ `delay_min_ms` after the swap |
| `database.sqlite_path` | string | `./honeypot.db` | any path; empty falls back to the default |
| `database.enable_wal` | boolean | `true` | — |
| `database.queue_capacity` | integer | `4096` | 16–1048576 |
| `database.busy_timeout_ms` | integer | `5000` | 50–60000 |
| `database.retention_days` | integer | `0` | 0–3650; `0` keeps every row |
| `database.max_size_bytes` | integer | `0` | `0` disables the size cap |
| `logging.level` | string | `info` | a `tracing` filter; invalid values fall back to `info` |
| `logging.log_queries` | boolean | `true` | — |
| `virtualdb.enabled` | boolean | `true` | — |
| `virtualdb.max_tables` | integer | `32` | 1–256 |
| `virtualdb.max_rows_per_table` | integer | `1000` | 1–100000 |
| `virtualdb.max_total_rows` | integer | `2000` | clamped to at least `max_rows_per_table`, at most 1000000 |
| `virtualdb.max_string_bytes` | integer | `1024` | 16–1048576 |
| `virtualdb.max_total_bytes` | integer | `65536` | 4096–67108864 |

`virtualdb.max_total_bytes` is the budget that matters for the container: 256
concurrent sessions × 64 KiB bounds the whole copy-on-write overlay at 16 MiB,
which is what makes `mem_limit: 128m` a safe ceiling rather than a guess. A
session that never writes allocates nothing at all.

### 1.1 Checking a config against the source

Two things have to hold, and both are checkable without building:

1. Every `[table]` and key in the TOML exists in `src/config.rs` under the same
   table name.
2. Every value the file sets is inside the range in the table above, otherwise
   it is silently clamped and the deployment does not run what the file says.

`config.docker.toml` sets exactly these 24 keys — nothing more:

```
server:        host, port, version, max_connections, idle_timeout_seconds,
               handshake_timeout_seconds, max_packet_size, max_sql_length,
               shutdown_grace_seconds
authentication: always_accept, delay_min_ms, delay_max_ms
database:      sqlite_path, enable_wal, queue_capacity, busy_timeout_ms
logging:       level, log_queries
virtualdb:     enabled, max_tables, max_rows_per_table, max_total_rows,
               max_string_bytes, max_total_bytes
```

---

## 2. What `config.docker.toml` changes, and why

| Setting | Container value | Reason |
| --- | --- | --- |
| `server.host` | `0.0.0.0` | the container has to accept traffic on its bridge interface, not on loopback |
| `database.sqlite_path` | `/data/honeypot.db` | `/data` is the only writable mount (root filesystem is read-only) |
| `server.shutdown_grace_seconds` | `10` | Docker's `stop_grace_period` is `20s`, so the drain window fits inside the SIGKILL deadline twice over |

Everything else is left at the built-in default.

---

## 3. Container limits

`docker-compose.yml` sets every limit explicitly; the `docker run` invocation in
the [main README](../README.md) mirrors them.

| Setting | Value | Effect |
| --- | --- | --- |
| `user` | `10001:10001` | matches the `USER` in the image; no root at any point |
| `read_only` | `true` | root filesystem is immutable; `/data` is the volume, `/tmp` is a tmpfs |
| `cap_drop` | `ALL` | port 3306 is above 1024, so no capability is needed |
| `security_opt` | `no-new-privileges:true` | a compromised process cannot gain privileges |
| `mem_limit` / `memswap_limit` | `128m` / `128m` | equal, so swap is off and the cap is hard |
| `oom_score_adj` | `500` | the decoy is the first process the kernel reclaims |
| `pids_limit` | `256` | bounds processes and threads; sessions are async tasks, so this does not cap connections |
| `ulimits.nofile` | `4096:8192` | soft/hard file descriptors |
| `logging` | `json-file`, `10m`, 3 files | hostile traffic cannot fill the host disk with logs |
| `stop_grace_period` | `20s` | longer than `shutdown_grace_seconds = 10`, so SIGTERM can flush the log queue |

The image publishes only `3306/tcp` and keeps the SQLite database on the
`honeypot-data` volume at `/data/honeypot.db`.

### 3.1 No `HEALTHCHECK`

The process speaks the MySQL protocol and nothing else, and the runtime image
carries no client that can speak it: `/bin/sh` is `dash`, which has no
`/dev/tcp`, and there is no `mysql` client or `nc`. A `HEALTHCHECK` would
therefore either fail permanently or force extra packages into the image, so it
is omitted on purpose and liveness is left to an operator-side TCP check on port
3306 (for example `nc -z 127.0.0.1 3306` from the host).

---

## 4. systemd unit

The unit targets **systemd 245 or newer** (Debian 11, Ubuntu 20.04 and later)
and uses only directives available on that baseline.

Paths, all consistent with each other:

| Directive | Value |
| --- | --- |
| `ExecStart` | `/usr/local/bin/mysql-honeypot-rs --config /etc/mysql-honeypot/config.toml` |
| `WorkingDirectory` | `/var/lib/mysql-honeypot` |
| `StateDirectory` | `mysql-honeypot` (i.e. `/var/lib/mysql-honeypot`, mode `0750`) |
| `ReadWritePaths` | `/var/lib/mysql-honeypot` |

Because `WorkingDirectory` is the state directory, a relative `sqlite_path`
lands next to the unit's own state; an absolute path (as in the container config)
overrides it.

File creation is owner-only (`UMask=0077`), so `honeypot.db` and its `-wal`/`-shm`
siblings are unreadable by other local accounts. The state directory keeps the
explicit `StateDirectoryMode=0750` — the umask does not override an explicitly
set mode.

Hardening beyond the defaults:

```
CapabilityBoundingSet=  AmbientCapabilities=     no capabilities at all
NoNewPrivileges=yes     PrivateTmp=yes           no setuid path, private /tmp
PrivateDevices=yes      ProtectSystem=strict     no device nodes, /usr /boot /etc read-only
ProtectHome=yes         ProtectClock=yes         no home directories, no clock changes
ProtectHostname=yes     ProtectKernelLogs=yes    no hostname or kernel-log access
ProtectKernelTunables=yes  ProtectKernelModules=yes  ProtectControlGroups=yes
ProtectProc=invisible   ProcSubset=pid           only the process's own /proc entries
RemoveIPC=yes           RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes  RestrictRealtime=yes     RestrictSUIDSGID=yes
LockPersonality=yes     MemoryDenyWriteExecute=yes
SystemCallArchitectures=native  SystemCallFilter=@system-service  SystemCallErrorNumber=EPERM
LimitNOFILE=8192        MemoryMax=256M
```

`PrivateUsers=` is deliberately **not** set: it would remap the service's UID and
make the `/data` ownership of an existing install wrong. `RestrictFileSystems=`
is not used either — it only exists from systemd 249 onwards.

`ProtectProc=` and `ProcSubset=` were introduced in systemd 247; on 245 they are
ignored with an "unknown key" log line and the unit still starts, so the unit
stay installable on the 245 baseline.

### 4.1 Install

```bash
sudo useradd --system --home-dir /var/lib/mysql-honeypot \
     --shell /usr/sbin/nologin mysql-honeypot
sudo install -d -m 0750 -o mysql-honeypot -g mysql-honeypot /var/lib/mysql-honeypot
sudo install -d -m 0755 /etc/mysql-honeypot
sudo install -m 0755 target/release/mysql-honeypot-rs /usr/local/bin/
sudo install -m 0640 -o root -g mysql-honeypot ../config.toml \
     /etc/mysql-honeypot/config.toml
sudo install -m 0644 mysql-honeypot-rs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mysql-honeypot-rs
```

`SIGTERM` stops the listener, closes live sessions, writes their
`disconnected_at`/`duration_ms` rows and flushes the log queue;
`TimeoutStopSec=20s` leaves room for the drain window configured in
`shutdown_grace_seconds` (default 5, clamped to 0–120).

---

## 5. Verifying a deployment

```bash
# the service is up and listening on exactly one port
systemctl status mysql-honeypot-rs
ss -lntp | grep mysql-honeypot-rs

# any credentials are accepted, so this should reach a prompt after the delay
mysql -h 127.0.0.1 -P 3306 -u anyone -pwhatever

# the audit trail is being written
sqlite3 /var/lib/mysql-honeypot/honeypot.db \
  "SELECT id, source_ip, username, auth_delay_ms FROM connections ORDER BY id DESC LIMIT 10;"
```

The end-to-end script covers the same ground automatically against a running
instance; see [`../scripts/README-e2e.md`](../scripts/README-e2e.md).
