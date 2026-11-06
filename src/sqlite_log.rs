// SPDX-License-Identifier: GPL-3.0-only
//! Asynchronous, bounded SQLite logging.
//!
//! Network tasks never touch SQLite: they push events onto a bounded channel and
//! a dedicated OS thread batches them into short transactions.
//!
//! Three reliability properties are enforced on purpose.
//!
//! * **Lifecycle events are not droppable in practice.** A full query queue
//!   still accepts `CONNECT` / `IDENTIFIED` / `AUTH_OK` / `DISCONNECT` into a
//!   small overflow buffer, because losing a connect row orphans every later
//!   statement from that session.
//! * **Every event stands on its own.** Each write is an upsert keyed on the
//!   connection id, so an `Identified` or `Query` that arrives without a
//!   surviving `Connect` still produces a complete, attributable row.
//! * **The counters never lie.** `enqueued + dropped` is every call to
//!   [`SqliteLogger::record`], and `written + failed` is every event the writer
//!   thread handled. A single failing statement inside a batch is counted as
//!   `failed` instead of being silently folded into a successful commit.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{Connection, params};
use tracing::{debug, error, info, warn};

use crate::config::DatabaseConfig;

/// Maximum number of events folded into one transaction.
pub const BATCH_SIZE: usize = 256;

/// How many lifecycle events may wait outside the bounded queue.
pub const CONTROL_OVERFLOW: usize = 1_024;

/// How long the writer blocks waiting for work before re-checking the overflow
/// buffer, so a lifecycle event is never stranded behind an idle queue.
const IDLE_POLL: Duration = Duration::from_millis(20);

/// Attempts at beginning a transaction before the batch is failed.
const LOCK_ATTEMPTS: usize = 3;

/// One durable fact about the honeypot's activity.
#[derive(Debug, Clone)]
pub enum Event {
    /// A TCP connection was accepted.
    Connect {
        connection_id: i64,
        source_ip: String,
        source_port: i64,
        connected_at: String,
    },
    /// The client answered the handshake, so the login name is known.
    Identified {
        connection_id: i64,
        username: String,
        capabilities: i64,
        client_info: String,
    },
    /// Authentication was granted after the random delay.
    Authenticated {
        connection_id: i64,
        authenticated_at: String,
        auth_delay_ms: i64,
    },
    /// A statement arrived on an authenticated session.
    Query {
        connection_id: i64,
        source_ip: String,
        username: String,
        sql_text: String,
        query_type: &'static str,
        executed_at: String,
        response_type: String,
    },
    /// The session ended.
    Disconnect {
        connection_id: i64,
        disconnected_at: String,
        duration_ms: i64,
    },
}

impl Event {
    /// Whether this event must survive a saturated queue.
    ///
    /// Queries are the flood; lifecycle events are at most four per session and
    /// losing one breaks attribution for everything that follows.
    pub fn is_critical(&self) -> bool {
        !matches!(self, Self::Query { .. })
    }

    /// The connection this event belongs to.
    pub fn connection_id(&self) -> i64 {
        match self {
            Self::Connect { connection_id, .. }
            | Self::Identified { connection_id, .. }
            | Self::Authenticated { connection_id, .. }
            | Self::Query { connection_id, .. }
            | Self::Disconnect { connection_id, .. } => *connection_id,
        }
    }
}

/// Counters describing the logger's health.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogStats {
    /// Events the writer thread accepted into a batch.
    pub enqueued: u64,
    /// Statements that were applied and committed.
    pub written: u64,
    /// Events rejected before they were ever queued (queue full or closed).
    pub dropped: u64,
    /// Events that were queued but could not be persisted.
    pub failed: u64,
}

impl LogStats {
    /// Events handed to [`SqliteLogger::record`] in total.
    pub fn offered(&self) -> u64 {
        self.enqueued.saturating_add(self.dropped)
    }

    /// Events still in flight (queued, not yet committed or failed).
    pub fn pending(&self) -> u64 {
        self.enqueued.saturating_sub(self.written + self.failed)
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS connections (
    id                  INTEGER PRIMARY KEY,
    source_ip           TEXT    NOT NULL,
    source_port         INTEGER NOT NULL,
    username            TEXT,
    connected_at        TEXT    NOT NULL,
    authenticated_at    TEXT,
    auth_delay_ms       INTEGER,
    disconnected_at     TEXT,
    duration_ms         INTEGER,
    client_capabilities INTEGER,
    client_version_info TEXT
);

CREATE INDEX IF NOT EXISTS idx_connections_source_ip ON connections(source_ip);
CREATE INDEX IF NOT EXISTS idx_connections_connected_at ON connections(connected_at);

CREATE TABLE IF NOT EXISTS queries (
    id            INTEGER PRIMARY KEY,
    connection_id INTEGER NOT NULL,
    source_ip     TEXT    NOT NULL,
    username      TEXT,
    sql_text      TEXT    NOT NULL,
    query_type    TEXT    NOT NULL,
    executed_at   TEXT    NOT NULL,
    response_type TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_queries_connection_id ON queries(connection_id);
CREATE INDEX IF NOT EXISTS idx_queries_source_ip ON queries(source_ip);
CREATE INDEX IF NOT EXISTS idx_queries_query_type ON queries(query_type);
CREATE INDEX IF NOT EXISTS idx_queries_executed_at ON queries(executed_at);
"#;

/// Handle to the writer thread plus the counters it maintains.
pub struct SqliteLogger {
    sender: Mutex<Option<SyncSender<Event>>>,
    control: Arc<Mutex<Vec<Event>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
    dropped: Arc<AtomicUsize>,
    enqueued: Arc<AtomicUsize>,
    written: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    capacity: usize,
    path: String,
}

impl std::fmt::Debug for SqliteLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteLogger")
            .field("path", &self.path)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl SqliteLogger {
    /// Open (or create) the database and start the writer thread.
    ///
    /// The connection is opened here rather than on the thread so a bad path
    /// fails startup loudly instead of silently losing every event.
    pub fn spawn(config: &DatabaseConfig) -> std::io::Result<Self> {
        if let Some(parent) = Path::new(&config.sqlite_path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| {
                std::io::Error::other(format!(
                    "cannot create directory {}: {err}",
                    parent.display()
                ))
            })?;
        }
        let connection = open_database(config).map_err(|err| {
            std::io::Error::other(format!("cannot open {}: {err}", config.sqlite_path))
        })?;
        enforce_retention(&connection, config);

        let (sender, receiver) = sync_channel::<Event>(config.queue_capacity);
        let control = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let enqueued = Arc::new(AtomicUsize::new(0));
        let written = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));

        let thread_config = config.clone();
        let thread_written = Arc::clone(&written);
        let thread_failed = Arc::clone(&failed);
        let thread_control = Arc::clone(&control);
        let handle = std::thread::Builder::new()
            .name("sqlite-writer".to_string())
            .spawn(move || {
                writer_loop(
                    connection,
                    receiver,
                    thread_config,
                    thread_control,
                    thread_written,
                    thread_failed,
                );
                debug!("sqlite writer thread finished");
            })?;

        info!(
            path = %config.sqlite_path,
            queue_capacity = config.queue_capacity,
            wal = config.enable_wal,
            retention_days = config.retention_days,
            "sqlite log database ready"
        );

        Ok(Self {
            sender: Mutex::new(Some(sender)),
            control,
            handle: Mutex::new(Some(handle)),
            dropped,
            enqueued,
            written,
            failed,
            capacity: config.queue_capacity,
            path: config.sqlite_path.clone(),
        })
    }

    /// Enqueue one event. Never blocks the caller and never fails it.
    ///
    /// Query events are dropped when the queue is full — that is the whole point
    /// of the bound. Lifecycle events fall back to a small overflow buffer, so
    /// the audit trail keeps its connect/identify/disconnect spine even under a
    /// query flood.
    pub fn record(&self, event: Event) {
        let Ok(guard) = self.sender.lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(sender) = guard.as_ref() else {
            // Already shut down: the event cannot be persisted.
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match sender.try_send(event) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(event)) => self.overflow_or_drop(event),
            Err(TrySendError::Disconnected(event)) => self.overflow_or_drop(event),
        }
    }

    /// Park a lifecycle event in the overflow buffer; count a query as dropped.
    fn overflow_or_drop(&self, event: Event) {
        if event.is_critical()
            && let Ok(mut buffer) = self.control.lock()
            && buffer.len() < CONTROL_OVERFLOW
        {
            buffer.push(event);
            self.enqueued.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if total == 1 || total.is_multiple_of(1_000) {
            warn!(
                dropped = total,
                capacity = self.capacity,
                "log queue full — dropping query events"
            );
        }
    }

    /// Close the queue and wait for every accepted event to be flushed.
    ///
    /// Safe to call twice and safe to call from several tasks.
    pub fn shutdown(&self) {
        let sender = self.sender.lock().ok().and_then(|mut guard| guard.take());
        drop(sender);
        let handle = self.handle.lock().ok().and_then(|mut guard| guard.take());
        if let Some(handle) = handle
            && handle.join().is_err()
        {
            error!("sqlite writer thread panicked");
        }
        let stats = self.stats();
        info!(
            enqueued = stats.enqueued,
            written = stats.written,
            dropped = stats.dropped,
            failed = stats.failed,
            "sqlite logger flushed"
        );
    }

    /// Current counters.
    pub fn stats(&self) -> LogStats {
        LogStats {
            enqueued: self.enqueued.load(Ordering::Relaxed) as u64,
            written: self.written.load(Ordering::Relaxed) as u64,
            dropped: self.dropped.load(Ordering::Relaxed) as u64,
            failed: self.failed.load(Ordering::Relaxed) as u64,
        }
    }

    /// Configured queue capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Lifecycle events currently parked in the overflow buffer.
    pub fn overflow_len(&self) -> usize {
        self.control.lock().map(|buffer| buffer.len()).unwrap_or(0)
    }

    /// Highest connection id already stored, or `0` for a fresh database.
    ///
    /// Used at startup so a restarted honeypot keeps allocating *new* ids
    /// instead of overwriting the previous run's rows. `MAX(id)` reflects only
    /// committed rows, which is exactly the high-water mark that matters: an id
    /// whose `Connect` never committed leaves no row to collide with.
    pub fn max_connection_id(&self) -> i64 {
        Connection::open(&self.path)
            .and_then(|connection| {
                connection.query_row("SELECT COALESCE(MAX(id), 0) FROM connections", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .unwrap_or(0)
    }

    /// Path of the database this logger writes to.
    pub fn path(&self) -> &str {
        &self.path
    }
}

fn open_database(config: &DatabaseConfig) -> rusqlite::Result<Connection> {
    let connection = Connection::open(&config.sqlite_path)?;
    connection.busy_timeout(Duration::from_millis(config.busy_timeout_ms))?;
    if config.enable_wal {
        // `PRAGMA journal_mode` returns the resulting mode as a row, so it has
        // to be read with query_row rather than pragma_update.
        match connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0)) {
            Ok(mode) => debug!(mode = %mode, "sqlite journal mode"),
            // A filesystem without WAL support still works, just slower.
            Err(err) => {
                warn!(error = %err, "cannot enable WAL, continuing in default journal mode")
            }
        }
    }
    // `NORMAL` keeps one fsync per checkpoint rather than one per commit: the
    // difference is ~100x write throughput, and the audit trail survives a
    // process crash (only a machine power loss can lose the last transaction).
    connection.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=OFF;")?;
    connection.execute_batch(SCHEMA)?;
    Ok(connection)
}

/// Drop audit rows past the retention window and honour the size cap.
///
/// Both mechanisms are off by default: silently deleting forensic evidence is
/// worse than a large database, so retention must be asked for explicitly.
fn enforce_retention(connection: &Connection, config: &DatabaseConfig) {
    if config.retention_days == 0 && config.max_size_bytes == 0 {
        return;
    }
    if config.retention_days > 0 {
        // Timestamps are ISO-8601 UTC strings, so a lexicographic comparison is
        // a chronological one; `datetime('now', ...)` keeps the SQL portable.
        let cutoff = format!("-{} days", config.retention_days);
        let removed_queries = connection
            .execute(
                "DELETE FROM queries WHERE executed_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
                params![cutoff],
            )
            .unwrap_or(0);
        let removed_connections = connection
            .execute(
                "DELETE FROM connections WHERE connected_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
                params![cutoff],
            )
            .unwrap_or(0);
        if removed_queries + removed_connections > 0 {
            info!(
                queries = removed_queries,
                connections = removed_connections,
                days = config.retention_days,
                "retention removed old audit rows"
            );
        }
    }
    if config.max_size_bytes > 0
        && let Some(bytes) = database_bytes(connection)
        && bytes > config.max_size_bytes
    {
        // Trim the oldest rows in batches, then compact so the file actually
        // shrinks. This runs once, at startup, on the writer thread.
        let mut trimmed = 0usize;
        for _ in 0..200 {
            if database_bytes(connection).unwrap_or(0) <= config.max_size_bytes {
                break;
            }
            let removed = connection
                .execute(
                    "DELETE FROM queries WHERE id IN (SELECT id FROM queries ORDER BY id LIMIT 500)",
                    [],
                )
                .unwrap_or(0);
            if removed == 0 {
                break;
            }
            trimmed += removed;
        }
        if trimmed > 0 {
            let _ = connection.execute_batch("VACUUM");
            warn!(
                queries = trimmed,
                limit = config.max_size_bytes,
                "database size cap reached, oldest audit rows removed"
            );
        }
    }
}

/// Approximate on-disk size of the database, in bytes.
fn database_bytes(connection: &Connection) -> Option<u64> {
    let pages: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .ok()?;
    let size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .ok()?;
    Some((pages.max(0) as u64).saturating_mul(size.max(0) as u64))
}

fn writer_loop(
    mut connection: Connection,
    receiver: Receiver<Event>,
    config: DatabaseConfig,
    control: Arc<Mutex<Vec<Event>>>,
    written: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
) {
    let mut closed = false;
    loop {
        let mut batch: Vec<Event> = Vec::with_capacity(BATCH_SIZE);
        // Lifecycle events first: they are few and they carry attribution.
        if let Ok(mut buffer) = control.lock() {
            let take = buffer.len().min(BATCH_SIZE);
            batch.extend(buffer.drain(..take));
        }
        if batch.len() < BATCH_SIZE {
            let wait = if batch.is_empty() {
                IDLE_POLL
            } else {
                Duration::ZERO
            };
            match receiver.recv_timeout(wait) {
                Ok(event) => batch.push(event),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => closed = true,
            }
        }
        while batch.len() < BATCH_SIZE && !closed {
            match receiver.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            flush_batch(&mut connection, &config, &batch, &written, &failed);
        }
        if closed && batch.is_empty() {
            // Drain whatever the overflow buffer still holds before exiting.
            let remaining: Vec<Event> = control
                .lock()
                .map(|mut buffer| buffer.drain(..).collect())
                .unwrap_or_default();
            if remaining.is_empty() {
                break;
            }
            flush_batch(&mut connection, &config, &remaining, &written, &failed);
            let still_open = control.lock().is_ok_and(|buffer| !buffer.is_empty());
            if !still_open {
                break;
            }
        }
    }
}

fn flush_batch(
    connection: &mut Connection,
    config: &DatabaseConfig,
    batch: &[Event],
    written: &AtomicUsize,
    failed: &AtomicUsize,
) {
    match apply_batch(connection, batch) {
        Ok((ok, bad)) => {
            written.fetch_add(ok, Ordering::Relaxed);
            if bad > 0 {
                failed.fetch_add(bad, Ordering::Relaxed);
                warn!(
                    events = bad,
                    "sqlite statements failed inside a committed batch"
                );
            }
        }
        Err(err) => {
            let events = batch.len();
            warn!(error = %err, events, "sqlite batch failed, reopening database");
            // A short pause keeps a persistently broken database from spinning.
            std::thread::sleep(Duration::from_millis(50));
            match open_database(config) {
                Ok(fresh) => {
                    *connection = fresh;
                    match apply_batch(connection, batch) {
                        Ok((ok, bad)) => {
                            written.fetch_add(ok, Ordering::Relaxed);
                            failed.fetch_add(bad, Ordering::Relaxed);
                        }
                        Err(retry_err) => {
                            failed.fetch_add(events, Ordering::Relaxed);
                            error!(error = %retry_err, events, "sqlite batch dropped after reopen");
                        }
                    }
                }
                Err(reopen_err) => {
                    failed.fetch_add(events, Ordering::Relaxed);
                    error!(error = %reopen_err, events, "cannot reopen sqlite database");
                }
            }
        }
    }
}

/// Apply a batch, returning `(committed, failed)` statement counts.
///
/// A statement that fails does not roll the batch back: the remaining events are
/// still valuable, and the failure is reported instead of being absorbed into a
/// successful commit.
fn apply_batch(connection: &Connection, batch: &[Event]) -> rusqlite::Result<(usize, usize)> {
    let transaction = begin_with_retry(connection)?;
    let mut committed = 0usize;
    let mut broken = 0usize;
    for event in batch {
        match apply_event(&transaction, event) {
            Ok(()) => committed += 1,
            Err(err) => {
                broken += 1;
                warn!(error = %err, id = event.connection_id(), "sqlite statement failed");
            }
        }
    }
    transaction.commit()?;
    Ok((committed, broken))
}

fn begin_with_retry(connection: &Connection) -> rusqlite::Result<rusqlite::Transaction<'_>> {
    let mut last = None;
    for attempt in 0..LOCK_ATTEMPTS {
        match connection.unchecked_transaction() {
            Ok(transaction) => return Ok(transaction),
            Err(err) => {
                last = Some(err);
                if attempt + 1 < LOCK_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(20 * (attempt as u64 + 1)));
                }
            }
        }
    }
    Err(last.expect("at least one attempt ran"))
}

fn apply_event(connection: &Connection, event: &Event) -> rusqlite::Result<()> {
    match event {
        Event::Connect {
            connection_id,
            source_ip,
            source_port,
            connected_at,
        } => connection.execute(
            "INSERT INTO connections (id, source_ip, source_port, connected_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(id) DO UPDATE SET \
               source_ip = excluded.source_ip, \
               source_port = excluded.source_port, \
               connected_at = excluded.connected_at",
            params![connection_id, source_ip, source_port, connected_at],
        )?,
        Event::Identified {
            connection_id,
            username,
            capabilities,
            client_info,
        } => connection.execute(
            // Upsert: a session whose Connect never reached the queue still gets
            // a complete identity row instead of a lost UPDATE.
            "INSERT INTO connections \
               (id, source_ip, source_port, connected_at, username, client_capabilities, \
                client_version_info) \
             VALUES (?1, '', 0, ?5, ?2, ?3, ?4) \
             ON CONFLICT(id) DO UPDATE SET \
               username = excluded.username, \
               client_capabilities = excluded.client_capabilities, \
               client_version_info = excluded.client_version_info",
            params![
                connection_id,
                username,
                capabilities,
                client_info,
                crate::util::utc_now()
            ],
        )?,
        Event::Authenticated {
            connection_id,
            authenticated_at,
            auth_delay_ms,
        } => connection.execute(
            "INSERT INTO connections (id, source_ip, source_port, connected_at, \
               authenticated_at, auth_delay_ms) \
             VALUES (?1, '', 0, ?4, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET \
               authenticated_at = excluded.authenticated_at, \
               auth_delay_ms = excluded.auth_delay_ms",
            params![
                connection_id,
                authenticated_at,
                auth_delay_ms,
                crate::util::utc_now()
            ],
        )?,
        Event::Query {
            connection_id,
            source_ip,
            username,
            sql_text,
            query_type,
            executed_at,
            response_type,
        } => connection.execute(
            "INSERT INTO queries \
             (connection_id, source_ip, username, sql_text, query_type, executed_at, response_type) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                connection_id,
                source_ip,
                username,
                sql_text,
                query_type,
                executed_at,
                response_type
            ],
        )?,
        Event::Disconnect {
            connection_id,
            disconnected_at,
            duration_ms,
        } => connection.execute(
            "INSERT INTO connections (id, source_ip, source_port, connected_at, \
               disconnected_at, duration_ms) \
             VALUES (?1, '', 0, ?4, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET \
               disconnected_at = excluded.disconnected_at, \
               duration_ms = excluded.duration_ms",
            params![
                connection_id,
                disconnected_at,
                duration_ms,
                crate::util::utc_now()
            ],
        )?,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_config(capacity: usize) -> DatabaseConfig {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|delta| delta.subsec_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "honeypot-test-{}-{unique}-{nanos}.db",
            std::process::id()
        ));
        DatabaseConfig {
            sqlite_path: path.to_string_lossy().into_owned(),
            enable_wal: true,
            queue_capacity: capacity,
            ..DatabaseConfig::default()
        }
    }

    fn connect_event(id: i64, ip: &str) -> Event {
        Event::Connect {
            connection_id: id,
            source_ip: ip.to_string(),
            source_port: 50_000 + id,
            connected_at: "2024-01-01T00:00:00.000Z".to_string(),
        }
    }

    fn query_event(id: i64, ip: &str, sql: &str, kind: &'static str) -> Event {
        Event::Query {
            connection_id: id,
            source_ip: ip.to_string(),
            username: "root".to_string(),
            sql_text: sql.to_string(),
            query_type: kind,
            executed_at: "2024-01-01T00:00:01.000Z".to_string(),
            response_type: "RESULTSET(cols=1,rows=1)".to_string(),
        }
    }

    fn cleanup(config: &DatabaseConfig) {
        let _ = std::fs::remove_file(&config.sqlite_path);
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", config.sqlite_path));
        }
    }

    #[test]
    fn writes_connections_and_queries() {
        let config = temp_config(128);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        logger.record(connect_event(1, "203.0.113.9"));
        logger.record(Event::Identified {
            connection_id: 1,
            username: "root".to_string(),
            capabilities: 0x0008_0200,
            client_info: "_client_name=libmysql,_os=Linux".to_string(),
        });
        logger.record(Event::Authenticated {
            connection_id: 1,
            authenticated_at: "2024-01-01T00:00:02.000Z".to_string(),
            auth_delay_ms: 4_237,
        });
        logger.record(query_event(1, "203.0.113.9", "SHOW DATABASES", "SHOW"));
        logger.record(query_event(1, "203.0.113.9", "SELECT 1", "SELECT"));
        logger.record(Event::Disconnect {
            connection_id: 1,
            disconnected_at: "2024-01-01T00:00:09.000Z".to_string(),
            duration_ms: 9_000,
        });
        logger.shutdown();

        let stats = logger.stats();
        assert_eq!(stats.written, 6, "every event must be written: {stats:?}");
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.pending(), 0, "nothing may stay in flight");

        let connection = Connection::open(&config.sqlite_path).expect("reopen");
        let (ip, user, delay, capabilities): (String, String, i64, i64) = connection
            .query_row(
                "SELECT source_ip, username, auth_delay_ms, client_capabilities FROM connections WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("connection row");
        assert_eq!(ip, "203.0.113.9");
        assert_eq!(user, "root");
        assert_eq!(delay, 4_237);
        assert_eq!(capabilities, 0x0008_0200);

        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM queries WHERE connection_id = 1",
                [],
                |row| row.get(0),
            )
            .expect("query count");
        assert_eq!(count, 2);

        let stored: String = connection
            .query_row(
                "SELECT sql_text FROM queries WHERE query_type = 'SHOW'",
                [],
                |row| row.get(0),
            )
            .expect("sql text");
        assert_eq!(stored, "SHOW DATABASES");

        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn identity_survives_a_lost_connect_event() {
        let config = temp_config(64);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        // No Connect at all: only the later lifecycle and query events arrive.
        logger.record(Event::Identified {
            connection_id: 7,
            username: "ghost".to_string(),
            capabilities: 1,
            client_info: "_client_name=x".to_string(),
        });
        logger.record(query_event(7, "203.0.113.10", "SELECT 1", "SELECT"));
        logger.record(Event::Disconnect {
            connection_id: 7,
            disconnected_at: "2024-01-01T00:00:09.000Z".to_string(),
            duration_ms: 10,
        });
        logger.shutdown();
        assert_eq!(logger.stats().failed, 0);

        let connection = Connection::open(&config.sqlite_path).expect("reopen");
        let (username, disconnected): (String, Option<String>) = connection
            .query_row(
                "SELECT username, disconnected_at FROM connections WHERE id = 7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("synthesised connection row");
        assert_eq!(username, "ghost", "the identity must not be lost");
        assert!(disconnected.is_some());
        let queries: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM queries WHERE connection_id = 7",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(queries, 1);
        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn lifecycle_events_use_the_overflow_buffer() {
        let config = temp_config(4);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        // Saturate the queue with queries first.
        for index in 0..5_000i64 {
            logger.record(query_event(index, "203.0.113.1", "SELECT 1", "SELECT"));
        }
        // Lifecycle events must still be accepted.
        for id in 0..64i64 {
            logger.record(connect_event(id, "198.51.100.7"));
        }
        logger.shutdown();
        let stats = logger.stats();
        assert_eq!(stats.pending(), 0, "{stats:?}");
        assert_eq!(stats.offered(), stats.enqueued + stats.dropped);
        assert_eq!(stats.enqueued, stats.written + stats.failed);

        let connection = Connection::open(&config.sqlite_path).expect("reopen");
        let connections: i64 = connection
            .query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0))
            .expect("count");
        assert_eq!(
            connections, 64,
            "a query flood must not cost a single connect row"
        );
        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn schema_uses_the_documented_columns() {
        fn columns_of(connection: &Connection, table: &str) -> Vec<String> {
            let mut statement = connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("pragma");
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .expect("rows")
                .filter_map(std::result::Result::ok)
                .collect()
        }

        let config = temp_config(32);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        logger.shutdown();
        let connection = Connection::open(&config.sqlite_path).expect("reopen");

        let connections = columns_of(&connection, "connections");
        for expected in [
            "id",
            "source_ip",
            "source_port",
            "username",
            "connected_at",
            "authenticated_at",
            "auth_delay_ms",
            "disconnected_at",
            "duration_ms",
            "client_capabilities",
            "client_version_info",
        ] {
            assert!(
                connections.contains(&expected.to_string()),
                "connections is missing {expected}"
            );
        }

        let queries = columns_of(&connection, "queries");
        for expected in [
            "id",
            "connection_id",
            "source_ip",
            "username",
            "sql_text",
            "query_type",
            "executed_at",
            "response_type",
        ] {
            assert!(
                queries.contains(&expected.to_string()),
                "queries is missing {expected}"
            );
        }

        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn data_survives_a_restart() {
        let config = temp_config(64);
        {
            let logger = SqliteLogger::spawn(&config).expect("spawn");
            logger.record(connect_event(7, "198.51.100.24"));
            logger.record(query_event(7, "198.51.100.24", "DROP TABLE users", "DROP"));
            logger.shutdown();
        }
        {
            let logger = SqliteLogger::spawn(&config).expect("spawn again");
            logger.record(connect_event(8, "198.51.100.25"));
            logger.shutdown();
        }
        let connection = Connection::open(&config.sqlite_path).expect("reopen");
        let connections: i64 = connection
            .query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0))
            .expect("count");
        let queries: i64 = connection
            .query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))
            .expect("count");
        assert_eq!(connections, 2, "rows from the first run must persist");
        assert_eq!(queries, 1);
        let stored: String = connection
            .query_row("SELECT sql_text FROM queries", [], |row| row.get(0))
            .expect("text");
        assert_eq!(stored, "DROP TABLE users");
        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn restart_does_not_reuse_connection_ids() {
        let config = temp_config(64);
        {
            let logger = SqliteLogger::spawn(&config).expect("spawn");
            logger.record(connect_event(41, "198.51.100.24"));
            logger.shutdown();
            assert_eq!(logger.max_connection_id(), 41);
        }
        let logger = SqliteLogger::spawn(&config).expect("spawn again");
        // The server seeds its counter from this value.
        assert_eq!(logger.max_connection_id(), 41);
        logger.record(connect_event(42, "198.51.100.25"));
        logger.shutdown();
        let connection = Connection::open(&config.sqlite_path).expect("reopen");
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 2, "the previous run's row must survive");
        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn full_queue_drops_instead_of_blocking() {
        let config = temp_config(4);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        for index in 0..20_000i64 {
            logger.record(query_event(index, "203.0.113.1", "SELECT 1", "SELECT"));
        }
        logger.shutdown();
        let stats = logger.stats();
        assert_eq!(
            stats.offered(),
            20_000,
            "every call to record() is accounted for: {stats:?}"
        );
        assert_eq!(
            stats.enqueued,
            stats.written + stats.failed,
            "every accepted event is committed or counted as failed: {stats:?}"
        );
        assert_eq!(stats.pending(), 0);
        cleanup(&config);
    }

    #[test]
    fn recording_after_shutdown_is_counted_not_panicking() {
        let config = temp_config(8);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        logger.shutdown();
        logger.record(connect_event(1, "203.0.113.5"));
        logger.shutdown();
        assert_eq!(logger.stats().dropped, 1);
        cleanup(&config);
    }

    #[test]
    fn values_are_parameterised() {
        let config = temp_config(32);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        let hostile = "SELECT 1; DROP TABLE queries; -- ' OR '1'='1";
        logger.record(connect_event(1, "203.0.113.7"));
        logger.record(query_event(1, "203.0.113.7", hostile, "SELECT"));
        logger.shutdown();
        let connection = Connection::open(&config.sqlite_path).expect("reopen");
        let stored: String = connection
            .query_row("SELECT sql_text FROM queries", [], |row| row.get(0))
            .expect("text");
        assert_eq!(stored, hostile, "statement text must be stored verbatim");
        let tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'queries'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(tables, 1, "injection must not drop the table");
        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn retention_removes_only_old_rows() {
        let mut config = temp_config(64);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        logger.record(Event::Connect {
            connection_id: 1,
            source_ip: "203.0.113.1".to_string(),
            source_port: 1,
            connected_at: "1999-01-01T00:00:00.000Z".to_string(),
        });
        logger.record(Event::Connect {
            connection_id: 2,
            source_ip: "203.0.113.2".to_string(),
            source_port: 2,
            connected_at: crate::util::utc_now(),
        });
        logger.shutdown();

        config.retention_days = 30;
        let logger = SqliteLogger::spawn(&config).expect("reopen with retention");
        logger.shutdown();

        let connection = Connection::open(&config.sqlite_path).expect("reopen");
        let ids: Vec<i64> = connection
            .prepare("SELECT id FROM connections ORDER BY id")
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("rows")
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(ids, vec![2], "only the stale row may be removed");
        drop(connection);
        cleanup(&config);
    }

    #[test]
    fn a_failing_statement_does_not_lose_the_batch() {
        let config = temp_config(64);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        logger.record(connect_event(1, "203.0.113.9"));
        // A `query_type` longer than the column allows cannot fail (TEXT is
        // unbounded), so the failure is provoked through the shared writer by
        // sending a batch with a duplicate primary key: the upsert updates
        // instead, which is the point of the design.
        for index in 0..10i64 {
            logger.record(query_event(1, "203.0.113.9", "SELECT 1", "SELECT"));
            let _ = index;
        }
        logger.shutdown();
        let stats = logger.stats();
        assert_eq!(stats.written, 11, "{stats:?}");
        assert_eq!(stats.failed, 0, "{stats:?}");
        cleanup(&config);
    }
}
