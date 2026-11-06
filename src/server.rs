// SPDX-License-Identifier: GPL-3.0-only
//! TCP listener, per-connection state machine and the authentication trap.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth;
use crate::config::Config;
use crate::fakedb::{self, FakeDatabase, QueryContext, QueryResult};
use crate::protocol::handshake;
use crate::protocol::packet::PacketStream;
use crate::protocol::response::{self, ColumnDef};
use crate::protocol::{
    self, CHARSET_UTF8MB4, CLIENT_PROTOCOL_41, Error as ProtocolError, SERVER_CAPABILITIES,
    SERVER_STATUS_AUTOCOMMIT,
};
use crate::sqlite_log::{Event, SqliteLogger};
use crate::util;

/// Longest SQL text echoed into a tracing line.
const LOG_SQL_PREVIEW: usize = 160;
/// Longest username persisted.
const LOG_USERNAME_LIMIT: usize = 128;
/// Longest client attribute string persisted.
const LOG_CLIENT_INFO_LIMIT: usize = 512;

/// Shared state for every session.
pub struct AppState {
    config: Config,
    logger: Arc<SqliteLogger>,
    database: FakeDatabase,
    started: SystemTime,
    connection_sequence: AtomicU64,
    active_connections: AtomicU64,
    permits: Arc<Semaphore>,
    /// Flipped to `true` when the listener starts shutting down, so open
    /// sessions finish, log their disconnect and release their slot.
    stop: tokio::sync::watch::Receiver<bool>,
}

impl AppState {
    /// Fake catalog served to clients.
    pub fn database(&self) -> &FakeDatabase {
        &self.database
    }

    /// Number of sessions currently open.
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Unix time the honeypot started.
    pub fn started(&self) -> SystemTime {
        self.started
    }
}

/// Start the honeypot on the configured address and run until a shutdown
/// signal arrives.
pub async fn run(config: Config) -> std::io::Result<()> {
    let logger = Arc::new(SqliteLogger::spawn(&config.database)?);
    // A tuple address goes through the resolver, so IPv4 literals, IPv6
    // literals (`::`) and host names all work without string surgery.
    let listener = TcpListener::bind((config.server.host.as_str(), config.server.port)).await?;
    let local = listener.local_addr()?;
    info!(
        address = %local,
        version = %config.server.version,
        max_connections = config.server.max_connections,
        "mysql honeypot listening (TCP only, no other ports)"
    );
    let outcome = serve(listener, config, Arc::clone(&logger), shutdown_signal()).await;
    logger.shutdown();
    outcome
}

/// Serve an already bound listener until `shutdown` resolves.
///
/// Exposed so integration tests can bind port `0` and drive the real server.
pub async fn serve<F>(
    listener: TcpListener,
    config: Config,
    logger: Arc<SqliteLogger>,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()>,
{
    let (stop_sender, stop) = tokio::sync::watch::channel(false);
    let state = Arc::new(AppState {
        permits: Arc::new(Semaphore::new(config.server.max_connections)),
        database: FakeDatabase::new(&config.server.version),
        started: SystemTime::now(),
        // Continue numbering where the previous run stopped: reusing ids would
        // replace older rows because `id` is the primary key.
        connection_sequence: AtomicU64::new(logger.max_connection_id().max(0) as u64 + 1),
        active_connections: AtomicU64::new(0),
        logger,
        config,
        stop,
    });
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let permits = Arc::clone(&state.permits);
                        match permits.try_acquire_owned() {
                            Ok(permit) => {
                                let session_state = Arc::clone(&state);
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    handle_client(session_state, stream, peer).await;
                                });
                            }
                            Err(_) => {
                                warn!(peer = %peer, limit = state.config.server.max_connections, "connection limit reached, refusing");
                                tokio::spawn(refuse_too_many_connections(stream));
                            }
                        }
                    }
                    Err(err) => {
                        // A transient accept error must not kill the listener.
                        warn!(error = %err, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            () = &mut shutdown => {
                info!("shutdown signal received, stopping listener");
                break;
            }
        }
    }

    drop(listener);
    // Tell every live session to wind down so its disconnect row is written.
    let _ = stop_sender.send(true);
    let grace = Duration::from_secs(state.config.server.shutdown_grace_seconds);
    let deadline = Instant::now() + grace;
    let mut remaining = state.active_connections();
    while remaining > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        remaining = state.active_connections();
    }
    if remaining > 0 {
        warn!(
            sessions = remaining,
            "grace period expired with sessions still open"
        );
    } else {
        info!("all sessions closed");
    }
    Ok(())
}

/// Keeps `active_connections` accurate even if a session task panics.
struct ActiveGuard {
    state: Arc<AppState>,
}

impl ActiveGuard {
    fn new(state: &Arc<AppState>) -> Self {
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            state: Arc::clone(state),
        }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.state
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Answer a client that arrived while the connection table was full, the same
/// way a real server does: an ERR packet before any handshake.
async fn refuse_too_many_connections(stream: TcpStream) {
    let mut packets = PacketStream::new(stream, 4096);
    packets.set_sequence(0);
    let payload = response::err_payload(
        CLIENT_PROTOCOL_41,
        protocol::ER_CON_COUNT_ERROR,
        "08004",
        "Too many connections",
    );
    let _ = packets.write_packet(&payload).await;
}

async fn handle_client(state: Arc<AppState>, stream: TcpStream, peer: SocketAddr) {
    let _guard = ActiveGuard::new(&state);
    let connection_id = state.connection_sequence.fetch_add(1, Ordering::Relaxed) as i64;
    let source_ip = peer.ip().to_string();
    let _ = stream.set_nodelay(true);

    info!(id = connection_id, peer = %peer, "CONNECT");
    state.logger.record(Event::Connect {
        connection_id,
        source_ip: source_ip.clone(),
        source_port: i64::from(peer.port()),
        connected_at: util::utc_now(),
    });

    let started = Instant::now();
    let mut session = Session {
        state: Arc::clone(&state),
        id: connection_id,
        source_ip: source_ip.clone(),
        username: String::new(),
        current_db: String::new(),
        capabilities: 0,
        queries: 0,
    };
    match session.run(stream).await {
        Ok(()) => debug!(id = connection_id, "session finished"),
        Err(err) => debug!(id = connection_id, error = %err, "session ended with a protocol error"),
    }

    let duration_ms = util::millis(started.elapsed()) as i64;
    info!(
        id = connection_id,
        peer = %peer,
        queries = session.queries,
        duration_ms,
        "DISCONNECT"
    );
    state.logger.record(Event::Disconnect {
        connection_id,
        disconnected_at: util::utc_now(),
        duration_ms,
    });
}

/// Per-connection protocol state.
struct Session {
    state: Arc<AppState>,
    id: i64,
    source_ip: String,
    username: String,
    current_db: String,
    capabilities: u32,
    queries: u64,
}

impl Session {
    async fn run(&mut self, stream: TcpStream) -> Result<(), ProtocolError> {
        let config = &self.state.config;
        let mut stop = self.state.stop.clone();
        let mut packets = PacketStream::new(stream, config.server.max_packet_size);

        // ---- initial handshake -------------------------------------------
        let salt = auth::random_salt();
        packets.set_sequence(0);
        let greeting = handshake::build_initial_handshake(
            self.id as u32,
            &config.server.version,
            &salt,
            SERVER_CAPABILITIES,
            CHARSET_UTF8MB4,
            SERVER_STATUS_AUTOCOMMIT,
            auth::handshake_plugin(),
        )?;
        packets.write_packet(&greeting).await?;
        info!(
            id = self.id,
            version = %config.server.version,
            plugin = auth::handshake_plugin(),
            "HANDSHAKE"
        );

        // ---- handshake response ------------------------------------------
        let handshake_timeout = Duration::from_secs(config.server.handshake_timeout_seconds);
        let payload = tokio::select! {
            biased;
            _ = stop.wait_for(|value| *value) => {
                info!(id = self.id, "shutdown before the handshake completed");
                return Ok(());
            }
            result = timeout(handshake_timeout, packets.read_packet()) => match result {
                Ok(Ok(payload)) => payload,
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    warn!(
                        id = self.id,
                        seconds = config.server.handshake_timeout_seconds,
                        "handshake timeout"
                    );
                    return Ok(());
                }
            },
        };

        if payload.is_empty() {
            return Err(ProtocolError::Malformed("empty handshake response"));
        }
        if handshake::is_ssl_request(&payload) {
            // TLS is not advertised and not implemented; say so instead of
            // pretending the session is encrypted.
            let payload = response::err_payload(
                CLIENT_PROTOCOL_41,
                protocol::ER_HANDSHAKE_ERROR,
                "08S01",
                "SSL connection error: the server does not support TLS",
            );
            packets.write_packet(&payload).await?;
            info!(id = self.id, "SSL_REQUEST refused");
            return Ok(());
        }

        let parsed = match handshake::parse_handshake_response(&payload) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(id = self.id, error = %err, "bad handshake response");
                let payload = response::err_payload(
                    CLIENT_PROTOCOL_41,
                    protocol::ER_HANDSHAKE_ERROR,
                    "08S01",
                    "Bad handshake",
                );
                packets.write_packet(&payload).await?;
                return Ok(());
            }
        };

        self.capabilities = parsed.capabilities;
        self.username = parsed.username.clone();
        if let Some(database) = parsed.database.as_ref().filter(|name| !name.is_empty()) {
            // Accept the requested schema blindly: refusing here would end a
            // promising session before the attacker does anything observable.
            self.current_db = database.clone();
        }
        let client_info = parsed.client_summary();
        info!(
            id = self.id,
            username = %clip(&self.username, LOG_USERNAME_LIMIT),
            database = %clip(&self.current_db, 64),
            plugin = parsed.auth_plugin.as_deref().unwrap_or("-"),
            "AUTH"
        );
        self.state.logger.record(Event::Identified {
            connection_id: self.id,
            username: clip(&self.username, LOG_USERNAME_LIMIT),
            capabilities: i64::from(parsed.capabilities),
            client_info: clip(&client_info, LOG_CLIENT_INFO_LIMIT),
        });

        // ---- the random delay trap ---------------------------------------
        let delay_ms = auth::random_delay_millis(&config.authentication);
        let delay_started = Instant::now();
        // Async sleep: the worker thread stays free for other clients, and the
        // wait is abandoned if the process is asked to stop.
        let interrupted = tokio::select! {
            biased;
            _ = stop.wait_for(|value| *value) => true,
            () = tokio::time::sleep(Duration::from_millis(delay_ms)) => false,
        };
        if interrupted {
            info!(
                id = self.id,
                "shutdown arrived during the authentication delay"
            );
            return Ok(());
        }
        let measured = util::millis(delay_started.elapsed());
        info!(
            id = self.id,
            delay_ms = measured,
            "DELAY {:.3}s",
            measured as f64 / 1000.0
        );

        // ---- authentication verdict --------------------------------------
        if !config.authentication.always_accept {
            // Comparative mode: behave like a real server with a wrong password.
            let message = format!(
                "Access denied for user '{}'@'localhost' (using password: YES)",
                clip(&self.username, LOG_USERNAME_LIMIT)
            );
            let payload = response::err_payload(
                self.capabilities,
                protocol::ER_ACCESS_DENIED_ERROR,
                "28000",
                &message,
            );
            packets.write_packet(&payload).await?;
            info!(id = self.id, "AUTH_DENIED (always_accept = false)");
            return Ok(());
        }

        let plan = auth::plan_for(parsed.auth_plugin.as_deref());
        if plan.needs_more_data() {
            // caching_sha2_password: report a cache hit so the client never
            // asks for an RSA key exchange we do not implement.
            packets
                .write_packet(&response::auth_more_data_payload(&[
                    auth::FAST_AUTH_SUCCESS,
                ]))
                .await?;
        }
        let ok = response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
        packets.write_packet(&ok).await?;
        info!(id = self.id, username = %clip(&self.username, LOG_USERNAME_LIMIT), "AUTH_OK");
        self.state.logger.record(Event::Authenticated {
            connection_id: self.id,
            authenticated_at: util::utc_now(),
            auth_delay_ms: measured as i64,
        });

        // ---- command loop -------------------------------------------------
        self.command_loop(&mut packets, &mut stop).await
    }

    async fn command_loop(
        &mut self,
        packets: &mut PacketStream<TcpStream>,
        stop: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), ProtocolError> {
        let idle = Duration::from_secs(self.state.config.server.idle_timeout_seconds);
        let id = self.id;
        loop {
            // Every client command starts a fresh sequence.
            packets.set_sequence(0);
            let payload = tokio::select! {
                biased;
                _ = stop.wait_for(|value| *value) => {
                    info!(id, "server shutting down, closing session");
                    return Ok(());
                }
                result = timeout(idle, packets.read_packet()) => match result {
                    Ok(Ok(payload)) => payload,
                    Ok(Err(ProtocolError::Eof)) => {
                        debug!(id, "client closed the connection");
                        return Ok(());
                    }
                    Ok(Err(err)) => {
                        warn!(id, error = %err, "protocol error, closing session");
                        return Ok(());
                    }
                    Err(_) => {
                        info!(
                            id,
                            seconds = self.state.config.server.idle_timeout_seconds,
                            "idle timeout"
                        );
                        return Ok(());
                    }
                },
            };

            let Some((&command, body)) = payload.split_first() else {
                warn!(id = self.id, "empty command packet");
                return Ok(());
            };

            match command {
                protocol::COM_QUIT => {
                    info!(id = self.id, "QUIT");
                    return Ok(());
                }
                protocol::COM_PING => {
                    let ok =
                        response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
                    packets.write_packet(&ok).await?;
                    debug!(id = self.id, "PING");
                }
                protocol::COM_INIT_DB => {
                    let name = String::from_utf8_lossy(body).to_string();
                    let known = self.state.database.has_schema(&name);
                    if known {
                        self.current_db = name.clone();
                    }
                    let payload = if known {
                        response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0)
                    } else {
                        response::err_payload(
                            self.capabilities,
                            protocol::ER_BAD_DB_ERROR,
                            "42000",
                            &format!("Unknown database '{}'", clip(&name, 64)),
                        )
                    };
                    packets.write_packet(&payload).await?;
                    info!(id = self.id, database = %clip(&name, 64), known, "INIT_DB");
                    self.record_query(
                        format!("USE {}", clip(&name, 64)),
                        "USE",
                        if known { "OK" } else { "ERR(1049)" },
                    );
                }
                protocol::COM_QUERY => {
                    let raw = String::from_utf8_lossy(body).to_string();
                    self.execute_query(packets, &raw).await?;
                }
                protocol::COM_FIELD_LIST => {
                    // Deprecated in 8.0; an empty list is the honest answer.
                    let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
                    packets.write_packet(&eof).await?;
                    debug!(id = self.id, "FIELD_LIST");
                }
                protocol::COM_STATISTICS => {
                    // Raw string payload, not a result set.
                    let text = "Uptime: 864000  Threads: 3  Questions: 91234  Slow queries: 0  \
                                Opens: 1533  Flush tables: 3  Open tables: 112  \
                                Queries per second avg: 0.105";
                    packets.write_packet(text.as_bytes()).await?;
                    debug!(id = self.id, "STATISTICS");
                }
                protocol::COM_PROCESS_INFO => {
                    let context = self.context();
                    let result = self.state.database.dispatch("SHOW PROCESSLIST", &context);
                    self.write_result(packets, result).await?;
                    debug!(id = self.id, "PROCESS_INFO");
                }
                protocol::COM_DEBUG => {
                    let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
                    packets.write_packet(&eof).await?;
                }
                protocol::COM_SET_OPTION => {
                    let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
                    packets.write_packet(&eof).await?;
                }
                protocol::COM_RESET_CONNECTION => {
                    self.current_db.clear();
                    let ok =
                        response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
                    packets.write_packet(&ok).await?;
                    debug!(id = self.id, "RESET_CONNECTION");
                }
                protocol::COM_CHANGE_USER => {
                    // Parse the new user name where possible; accept regardless.
                    let mut reader = protocol::packet::PayloadReader::new(body);
                    if let Ok(name) = reader.nul_str()
                        && !name.is_empty()
                    {
                        self.username = name;
                    }
                    let ok =
                        response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
                    packets.write_packet(&ok).await?;
                    info!(id = self.id, username = %clip(&self.username, LOG_USERNAME_LIMIT), "CHANGE_USER");
                }
                protocol::COM_STMT_PREPARE => {
                    // The binary protocol is out of scope; log the SQL anyway so
                    // the attempt is visible in the audit trail.
                    let raw = String::from_utf8_lossy(body).to_string();
                    let (text, _) =
                        util::truncate_to(&raw, self.state.config.server.max_sql_length);
                    info!(id = self.id, sql = %preview(&text), "STMT_PREPARE unsupported");
                    self.record_query(text, "PREPARE", "ERR(1295)");
                    let payload = response::err_payload(
                        self.capabilities,
                        protocol::ER_UNSUPPORTED_PS,
                        "HY000",
                        "This command is not supported in the prepared statement protocol yet",
                    );
                    packets.write_packet(&payload).await?;
                }
                protocol::COM_STMT_EXECUTE => {
                    let payload = response::err_payload(
                        self.capabilities,
                        1243,
                        "HY000",
                        "Unknown prepared statement handler given to mysqld_stmt_execute",
                    );
                    packets.write_packet(&payload).await?;
                }
                protocol::COM_STMT_CLOSE => {
                    // No response is expected for a close.
                    debug!(id = self.id, "STMT_CLOSE");
                }
                0x1a => {
                    // COM_STMT_RESET
                    let ok =
                        response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
                    packets.write_packet(&ok).await?;
                }
                other => {
                    warn!(id = self.id, command = other, "unknown command");
                    let payload = response::err_payload(
                        self.capabilities,
                        protocol::ER_UNKNOWN_COM_ERROR,
                        "08S01",
                        "Unknown command",
                    );
                    packets.write_packet(&payload).await?;
                }
            }
        }
    }

    fn context(&self) -> QueryContext {
        QueryContext {
            current_db: self.current_db.clone(),
            username: self.username.clone(),
            connection_id: self.id as u32,
            server_version: self.state.config.server.version.clone(),
        }
    }

    async fn execute_query(
        &mut self,
        packets: &mut PacketStream<TcpStream>,
        raw: &str,
    ) -> Result<(), ProtocolError> {
        self.queries += 1;
        let limit = self.state.config.server.max_sql_length;
        let (sql_text, truncated) = util::truncate_to(raw, limit);
        let query_type = fakedb::classify(&sql_text);
        let context = self.context();
        let result = self.state.database.dispatch(&sql_text, &context);

        // `USE` changes the session's schema, exactly like a real server.
        if let Some(name) = fakedb::use_target(&sql_text)
            && self.state.database.has_schema(&name)
        {
            self.current_db = name;
        }

        if self.state.config.logging.log_queries {
            info!(
                id = self.id,
                kind = query_type,
                truncated,
                sql = %preview(&sql_text),
                "QUERY"
            );
        }
        self.record_query(sql_text, query_type, &result.kind());
        self.write_result(packets, result).await
    }

    fn record_query(&self, sql_text: String, query_type: &'static str, response_type: &str) {
        self.state.logger.record(Event::Query {
            connection_id: self.id,
            source_ip: self.source_ip.clone(),
            username: clip(&self.username, LOG_USERNAME_LIMIT),
            sql_text,
            query_type,
            executed_at: util::utc_now(),
            response_type: clip(response_type, 128),
        });
    }

    async fn write_result(
        &mut self,
        packets: &mut PacketStream<TcpStream>,
        result: QueryResult,
    ) -> Result<(), ProtocolError> {
        match result {
            QueryResult::Ok {
                affected_rows,
                last_insert_id,
                ..
            } => {
                let payload = response::ok_payload(
                    self.capabilities,
                    affected_rows,
                    last_insert_id,
                    SERVER_STATUS_AUTOCOMMIT,
                    0,
                );
                packets.write_packet(&payload).await?;
            }
            QueryResult::ResultSet(set) => {
                let columns: Vec<ColumnDef<'_>> = set
                    .columns
                    .iter()
                    .map(|column| ColumnDef {
                        schema: &column.schema,
                        table: &column.table,
                        org_table: &column.table,
                        name: &column.name,
                        org_name: &column.org_name,
                        charset: u32::from(CHARSET_UTF8MB4) as u16,
                        column_length: 1024,
                        column_type: column.wire_type,
                        flags: 0,
                        decimals: 0,
                    })
                    .collect();
                response::write_result_set(
                    packets,
                    self.capabilities,
                    &columns,
                    &set.rows,
                    SERVER_STATUS_AUTOCOMMIT,
                )
                .await?;
            }
            QueryResult::Error {
                code,
                sqlstate,
                message,
            } => {
                let payload = response::err_payload(self.capabilities, code, sqlstate, &message);
                packets.write_packet(&payload).await?;
            }
            QueryResult::Eof => {
                let payload = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
                packets.write_packet(&payload).await?;
            }
        }
        Ok(())
    }
}

/// UTF-8 safe clip for log and database fields.
fn clip(text: &str, max_bytes: usize) -> String {
    util::truncate_to(text, max_bytes).0
}

/// Collapse control characters so a hostile statement cannot forge log lines.
fn preview(sql: &str) -> String {
    let (text, _) = util::truncate_to(sql, LOG_SQL_PREVIEW);
    text.chars()
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(err) => {
            warn!(error = %err, "cannot install SIGTERM handler, waiting for Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("received SIGINT"),
        _ = terminate.recv() => info!("received SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("received interrupt");
}
