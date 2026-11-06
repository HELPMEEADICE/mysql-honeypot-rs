// SPDX-License-Identifier: GPL-3.0-only
//! Asynchronous, bounded SQLite logging.
//!
//! Network tasks never touch SQLite: they push events onto a bounded channel
//! and a dedicated OS thread batches them into short transactions. A full
//! queue drops events and counts them instead of stalling a session or growing
//! memory without bound.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{Connection, params};
use tracing::{debug, error, info, warn};

use crate::config::DatabaseConfig;

/// Maximum number of events folded into one transaction.
pub const BATCH_SIZE: usize = 256;

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

/// Counters describing the logger's health.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogStats {
    /// Events accepted by the writer thread.
    pub written: u64,
    /// Events rejected because the queue was full or already closed.
    pub dropped: u64,
    /// Events that reached the writer but could not be persisted.
    pub failed: u64,
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
    handle: Mutex<Option<JoinHandle<()>>>,
    dropped: Arc<AtomicUsize>,
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

        let (sender, receiver) = sync_channel::<Event>(config.queue_capacity);
        let dropped = Arc::new(AtomicUsize::new(0));
        let written = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));

        let thread_config = config.clone();
        let thread_written = Arc::clone(&written);
        let thread_failed = Arc::clone(&failed);
        let handle = std::thread::Builder::new()
            .name("sqlite-writer".to_string())
            .spawn(move || {
                writer_loop(
                    connection,
                    receiver,
                    thread_config,
                    thread_written,
                    thread_failed,
                );
                debug!("sqlite writer thread finished");
            })?;

        info!(
            path = %config.sqlite_path,
            queue_capacity = config.queue_capacity,
            wal = config.enable_wal,
            "sqlite log database ready"
        );

        Ok(Self {
            sender: Mutex::new(Some(sender)),
            handle: Mutex::new(Some(handle)),
            dropped,
            written,
            failed,
            capacity: config.queue_capacity,
            path: config.sqlite_path.clone(),
        })
    }

    /// Enqueue one event. Never blocks and never fails the caller.
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
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if total == 1 || total.is_multiple_of(1_000) {
                    warn!(
                        dropped = total,
                        capacity = self.capacity,
                        "log queue full — dropping events"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
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
            written = stats.written,
            dropped = stats.dropped,
            failed = stats.failed,
            "sqlite logger flushed"
        );
    }

    /// Current counters.
    pub fn stats(&self) -> LogStats {
        LogStats {
            written: self.written.load(Ordering::Relaxed) as u64,
            dropped: self.dropped.load(Ordering::Relaxed) as u64,
            failed: self.failed.load(Ordering::Relaxed) as u64,
        }
    }

    /// Configured queue capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Highest connection id already stored, or `0` for a fresh database.
    ///
    /// Used at startup so a restarted honeypot keeps allocating *new* ids
    /// instead of overwriting the previous run's rows.
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
    connection.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=OFF;")?;
    connection.execute_batch(SCHEMA)?;
    Ok(connection)
}

fn writer_loop(
    mut connection: Connection,
    receiver: Receiver<Event>,
    config: DatabaseConfig,
    written: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
) {
    let mut batch: Vec<Event> = Vec::with_capacity(BATCH_SIZE);
    // Blocking receive is correct here: this thread owns the database.
    while let Ok(first) = receiver.recv() {
        batch.push(first);
        while batch.len() < BATCH_SIZE {
            match receiver.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }

        let count = batch.len();
        match apply_batch(&connection, &batch) {
            Ok(()) => {
                written.fetch_add(count, Ordering::Relaxed);
            }
            Err(err) => {
                warn!(error = %err, events = count, "sqlite batch failed, reopening database");
                match open_database(&config) {
                    Ok(fresh) => {
                        connection = fresh;
                        match apply_batch(&connection, &batch) {
                            Ok(()) => {
                                written.fetch_add(count, Ordering::Relaxed);
                            }
                            Err(retry_err) => {
                                failed.fetch_add(count, Ordering::Relaxed);
                                error!(error = %retry_err, events = count, "sqlite batch dropped after reopen");
                            }
                        }
                    }
                    Err(reopen_err) => {
                        failed.fetch_add(count, Ordering::Relaxed);
                        error!(error = %reopen_err, events = count, "cannot reopen sqlite database");
                    }
                }
            }
        }
        batch.clear();
    }
}

fn apply_batch(connection: &Connection, batch: &[Event]) -> rusqlite::Result<()> {
    let transaction = connection.unchecked_transaction()?;
    for event in batch {
        if let Err(err) = apply_event(&transaction, event) {
            // One bad row must not lose the rest of the batch.
            warn!(error = %err, "sqlite statement failed");
        }
    }
    transaction.commit()
}

fn apply_event(connection: &Connection, event: &Event) -> rusqlite::Result<()> {
    match event {
        Event::Connect {
            connection_id,
            source_ip,
            source_port,
            connected_at,
        } => connection.execute(
            "INSERT OR REPLACE INTO connections (id, source_ip, source_port, connected_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![connection_id, source_ip, source_port, connected_at],
        )?,
        Event::Identified {
            connection_id,
            username,
            capabilities,
            client_info,
        } => connection.execute(
            "UPDATE connections SET username = ?2, client_capabilities = ?3, \
             client_version_info = ?4 WHERE id = ?1",
            params![connection_id, username, capabilities, client_info],
        )?,
        Event::Authenticated {
            connection_id,
            authenticated_at,
            auth_delay_ms,
        } => connection.execute(
            "UPDATE connections SET authenticated_at = ?2, auth_delay_ms = ?3 WHERE id = ?1",
            params![connection_id, authenticated_at, auth_delay_ms],
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
            "UPDATE connections SET disconnected_at = ?2, duration_ms = ?3 WHERE id = ?1",
            params![connection_id, disconnected_at, duration_ms],
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
            busy_timeout_ms: 2_000,
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
        assert_eq!(stats.written, 6, "every event must be written");
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.failed, 0);

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
        let _ = std::fs::remove_file(&config.sqlite_path);
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", config.sqlite_path));
        }
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
        let _ = std::fs::remove_file(&config.sqlite_path);
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
        let _ = std::fs::remove_file(&config.sqlite_path);
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", config.sqlite_path));
        }
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
            stats.written + stats.dropped + stats.failed,
            20_000,
            "every event is either written or counted as dropped: {stats:?}"
        );
        let _ = std::fs::remove_file(&config.sqlite_path);
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", config.sqlite_path));
        }
    }

    #[test]
    fn recording_after_shutdown_is_counted_not_panicking() {
        let config = temp_config(8);
        let logger = SqliteLogger::spawn(&config).expect("spawn");
        logger.shutdown();
        logger.record(connect_event(1, "203.0.113.5"));
        logger.shutdown();
        assert_eq!(logger.stats().dropped, 1);
        let _ = std::fs::remove_file(&config.sqlite_path);
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
        let _ = std::fs::remove_file(&config.sqlite_path);
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", config.sqlite_path));
        }
    }
}
