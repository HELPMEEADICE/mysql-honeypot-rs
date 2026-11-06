// SPDX-License-Identifier: GPL-3.0-only
//! TCP listener, per-connection state machine and the authentication trap.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth;
use crate::config::Config;
use crate::fakedb::{self, FakeDatabase, QueryContext, QueryResult, SessionState};
use crate::protocol::execute;
use crate::protocol::handshake;
use crate::protocol::packet::{PacketStream, PayloadReader};
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
/// Prepared statements one session may hold open.
const MAX_PREPARED_STATEMENTS: usize = 32;

/// Total statement text one session may pin with prepared statements.
///
/// `max_sql_length` bounds one statement; without a second bound a client could
/// hold `MAX_PREPARED_STATEMENTS` statements of the maximum length open on every
/// connection at once.
const MAX_PREPARED_SQL_BYTES: usize = 64 * 1024;

/// Bound on the rendered statement written to the audit database.
///
/// A prepared statement's bound values are rendered into the audit row so the
/// record matches what actually executed; the rendering is clipped so a page of
/// oversized parameters cannot bloat one audit row without limit.
const MAX_AUDIT_SQL_BYTES: usize = 32 * 1024;
/// Refusal replies that may be in flight at once.
///
/// Without this cap, a connection flood turns every rejected socket into a
/// spawned task, which is a cheaper attack than exhausting the connection table.
const MAX_REFUSAL_TASKS: usize = 32;
/// Column payload size advertised for text columns.
const TEXT_COLUMN_LENGTH: u32 = 1024;

/// Shared state for every session.
pub struct AppState {
    config: Config,
    logger: Arc<SqliteLogger>,
    database: FakeDatabase,
    started: SystemTime,
    connection_sequence: AtomicUsize,
    active_connections: AtomicUsize,
    permits: Arc<Semaphore>,
    refusals: Arc<Semaphore>,
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
        self.active_connections.load(Ordering::Relaxed) as u64
    }

    /// Unix time the honeypot started.
    pub fn started(&self) -> SystemTime {
        self.started
    }

    fn new_state(&self) -> SessionState {
        SessionState::new(self.config.virtualdb.budgets())
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
        refusals: Arc::new(Semaphore::new(MAX_REFUSAL_TASKS)),
        database: FakeDatabase::new(&config.server.version),
        started: SystemTime::now(),
        // Continue numbering where the previous run stopped: reusing ids would
        // replace older rows because `id` is the primary key.
        // `AtomicUsize` rather than `AtomicU64`: targets such as 32-bit MIPS have
        // no 64-bit atomics, so `AtomicU64` does not even exist there.
        connection_sequence: AtomicUsize::new(
            (logger.max_connection_id().max(0) as usize).saturating_add(1),
        ),
        active_connections: AtomicUsize::new(0),
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
                                // Bounded: once MAX_REFUSAL_TASKS replies are in
                                // flight the socket is simply closed, so a flood
                                // cannot spawn unbounded tasks.
                                match Arc::clone(&state.refusals).try_acquire_owned() {
                                    Ok(refusal) => {
                                        let limit = state.config.server.max_connections;
                                        warn!(peer = %peer, limit, "connection limit reached, refusing");
                                        tokio::spawn(async move {
                                            let _refusal = refusal;
                                            refuse_too_many_connections(stream).await;
                                        });
                                    }
                                    Err(_) => {
                                        debug!(peer = %peer, "refusal budget exhausted, closing socket");
                                        drop(stream);
                                    }
                                }
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
        virtual_db: state.new_state(),
        state: Arc::clone(&state),
        id: connection_id,
        source_ip: source_ip.clone(),
        username: String::new(),
        current_db: String::new(),
        capabilities: 0,
        queries: 0,
        prepared: Vec::new(),
        next_statement_id: 1,
        last_result: None,
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

/// One prepared statement kept for the session's lifetime.
struct PreparedStatement {
    id: u32,
    sql: String,
    /// Placeholder count recorded at prepare time.
    param_count: usize,
    /// Parameter types of the previous execute, reused when the client clears
    /// `new_params_bound_flag`.
    param_types: Vec<execute::ParamType>,
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
    /// The session's copy-on-write virtual database.
    virtual_db: SessionState,
    prepared: Vec<PreparedStatement>,
    next_statement_id: u32,
    /// Response produced by the last `COM_QUERY`, written by the command loop.
    last_result: Option<QueryResult>,
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
        // Bound the identity the session keeps in memory: the handshake payload
        // is client controlled and can be most of a megabyte long, and this value
        // lives for the whole session and feeds every log line.
        self.username = clip(&parsed.username, LOG_USERNAME_LIMIT);
        if let Some(database) = parsed.database.as_ref().filter(|name| !name.is_empty()) {
            // The catalog must never contradict itself: an unknown schema is not
            // adopted, so `DATABASE()` stays NULL instead of naming a database
            // that `SHOW TABLES` would then refuse to describe.
            if self.state.database.has_schema(database, &self.virtual_db) {
                self.current_db = database.clone();
            } else {
                info!(
                    id = self.id,
                    requested = %log_field(database, 64),
                    "handshake named an unknown database, ignoring it"
                );
            }
        }
        let client_info = parsed.client_summary();
        info!(
            id = self.id,
            username = %log_field(&self.username, LOG_USERNAME_LIMIT),
            database = %log_field(&self.current_db, 64),
            plugin = log_field(parsed.auth_plugin.as_deref().unwrap_or("-"), 64),
            "AUTH"
        );
        self.state.logger.record(Event::Identified {
            connection_id: self.id,
            username: log_field(&self.username, LOG_USERNAME_LIMIT),
            capabilities: i64::from(parsed.capabilities),
            client_info: log_field(&client_info, LOG_CLIENT_INFO_LIMIT),
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
                log_field(&self.username, LOG_USERNAME_LIMIT)
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
        info!(id = self.id, username = %log_field(&self.username, LOG_USERNAME_LIMIT), "AUTH_OK");
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
                    let known = self.state.database.has_schema(&name, &self.virtual_db);
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
                            &format!("Unknown database '{}'", log_field(&name, 64)),
                        )
                    };
                    packets.write_packet(&payload).await?;
                    info!(id = self.id, database = %log_field(&name, 64), known, "INIT_DB");
                    self.record_query(
                        format!("USE {}", log_field(&name, 64)),
                        "USE",
                        if known { "OK" } else { "ERR(1049)" },
                    );
                }
                protocol::COM_QUERY => {
                    let raw = String::from_utf8_lossy(body).to_string();
                    self.execute_query(&raw).await?;
                    let result = self.last_result.take().unwrap_or(QueryResult::Eof);
                    self.write_result(packets, result).await?;
                }
                protocol::COM_FIELD_LIST => {
                    let table = String::from_utf8_lossy(body).to_string();
                    self.write_field_list(packets, &table).await?;
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
                    let mut state = std::mem::take(&mut self.virtual_db);
                    let result =
                        self.state
                            .database
                            .dispatch("SHOW PROCESSLIST", &context, &mut state);
                    self.virtual_db = state;
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
                    self.virtual_db.reset();
                    self.prepared.clear();
                    let ok =
                        response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
                    packets.write_packet(&ok).await?;
                    debug!(id = self.id, "RESET_CONNECTION");
                }
                protocol::COM_CHANGE_USER => {
                    self.change_user(packets, body).await?;
                }
                protocol::COM_STMT_PREPARE => {
                    self.prepare_statement(packets, body).await?;
                }
                protocol::COM_STMT_EXECUTE => {
                    self.execute_prepared(packets, body).await?;
                }
                protocol::COM_STMT_CLOSE => {
                    // No response is expected for a close.
                    if let Some((id, _)) = split_statement_id(body) {
                        self.prepared.retain(|statement| statement.id != id);
                    }
                    debug!(id = self.id, "STMT_CLOSE");
                }
                protocol::COM_STMT_SEND_LONG_DATA => {
                    // Fire and forget: no response packet, and the payload is
                    // discarded because no statement ever needs real parameters.
                    debug!(id = self.id, "STMT_SEND_LONG_DATA");
                }
                protocol::COM_STMT_RESET => {
                    // `COM_STMT_RESET` discards accumulated long data and the
                    // cached parameter types, so the next execute must resend
                    // them. Answering OK without clearing them would let a client
                    // reuse a stale type block and get wrong values bound.
                    if let Some((id, _)) = split_statement_id(body)
                        && let Some(statement) = self
                            .prepared
                            .iter_mut()
                            .find(|statement| statement.id == id)
                    {
                        statement.param_types.clear();
                    }
                    let ok =
                        response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
                    packets.write_packet(&ok).await?;
                    debug!(id = self.id, "STMT_RESET");
                }
                protocol::COM_STMT_FETCH => {
                    // Cursors are not implemented; say so rather than sending a
                    // partial result the client would mis-frame.
                    let payload = response::err_payload(
                        self.capabilities,
                        protocol::ER_UNSUPPORTED_PS,
                        "HY000",
                        "This command is not supported in the prepared statement protocol yet",
                    );
                    packets.write_packet(&payload).await?;
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

    /// `COM_CHANGE_USER`: adopt the new identity, database and plugin, then
    /// confirm with an OK packet the way a real server does.
    async fn change_user(
        &mut self,
        packets: &mut PacketStream<TcpStream>,
        body: &[u8],
    ) -> Result<(), ProtocolError> {
        let previous_user = self.username.clone();
        let previous_db = self.current_db.clone();
        let mut reader = PayloadReader::new(body);
        let new_user = reader.nul_str().unwrap_or_default();
        // Authentication response: a one byte length followed by that many
        // bytes. The value is never used, only skipped.
        let auth_length = reader.u8().unwrap_or(0) as usize;
        let _ = reader.skip(auth_length);
        let new_db = reader.nul_str().unwrap_or_default();
        // charset (2 bytes) then the plugin name.
        let _ = reader.u16le();
        let plugin = reader.nul_str().unwrap_or_default();

        if !new_user.is_empty() {
            self.username = clip(&new_user, LOG_USERNAME_LIMIT);
        }
        // A new user gets a clean virtual database, exactly like MySQL resetting
        // the session on `COM_CHANGE_USER`.
        self.virtual_db.reset();
        self.current_db.clear();
        if !new_db.is_empty() && self.state.database.has_schema(&new_db, &self.virtual_db) {
            self.current_db = new_db.clone();
        }
        self.prepared.clear();

        let ok = response::ok_payload(self.capabilities, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
        packets.write_packet(&ok).await?;
        info!(
            id = self.id,
            from = %log_field(&previous_user, LOG_USERNAME_LIMIT),
            to = %log_field(&self.username, LOG_USERNAME_LIMIT),
            database = %log_field(&self.current_db, 64),
            plugin = log_field(&plugin, 64),
            "CHANGE_USER"
        );
        // Keep the audit trail consistent: the connections row must name the
        // identity the session is using now, and the switch itself is recorded.
        self.state.logger.record(Event::Identified {
            connection_id: self.id,
            username: log_field(&self.username, LOG_USERNAME_LIMIT),
            capabilities: i64::from(self.capabilities),
            client_info: "COM_CHANGE_USER".to_string(),
        });
        self.record_query(
            format!(
                "COM_CHANGE_USER {} -> {} (db {} -> {})",
                log_field(&previous_user, 64),
                log_field(&self.username, 64),
                log_field(&previous_db, 64),
                log_field(&self.current_db, 64)
            ),
            "CHANGE_USER",
            "OK",
        );
        Ok(())
    }

    /// `COM_STMT_PREPARE`: answer with `COM_STMT_PREPARE_OK` plus parameter and
    /// column definitions, so drivers that insist on the binary protocol work.
    async fn prepare_statement(
        &mut self,
        packets: &mut PacketStream<TcpStream>,
        body: &[u8],
    ) -> Result<(), ProtocolError> {
        let raw = String::from_utf8_lossy(body).to_string();
        let (sql, truncated) = util::truncate_to(&raw, self.state.config.server.max_sql_length);
        // The tokenizer is the reference for how many placeholders the statement
        // really contains: a `?` inside a literal or a comment is not one.
        let parameters = fakedb::sql::count_placeholders(&sql);
        if parameters > u16::MAX as usize {
            let payload = response::err_payload(
                self.capabilities,
                protocol::ER_UNSUPPORTED_PS,
                "HY000",
                "Too many placeholders",
            );
            packets.write_packet(&payload).await?;
            return Ok(());
        }
        let statement_id = self.next_statement_id;
        self.next_statement_id = self.next_statement_id.wrapping_add(1).max(1);
        // Two bounds, both needed: the count alone would still let a client pin
        // `MAX_PREPARED_STATEMENTS` maximum-length statements per connection.
        while !self.prepared.is_empty()
            && (self.prepared.len() >= MAX_PREPARED_STATEMENTS
                || self
                    .prepared
                    .iter()
                    .map(|statement| statement.sql.len())
                    .sum::<usize>()
                    .saturating_add(sql.len())
                    > MAX_PREPARED_SQL_BYTES)
        {
            self.prepared.remove(0);
        }
        self.prepared.push(PreparedStatement {
            id: statement_id,
            sql: sql.clone(),
            param_count: parameters,
            param_types: Vec::new(),
        });

        // Metadata the client will read immediately after the OK packet: the
        // parameter definitions, then one definition per result column. Both
        // blocks are terminated by EOF unless CLIENT_DEPRECATE_EOF is set.
        let columns = self.prepared_column_payloads(&sql);
        let payload = response::stmt_prepare_ok_payload(
            statement_id,
            u16::try_from(columns.len()).unwrap_or(0),
            parameters as u16,
            0,
        );
        packets.write_packet(&payload).await?;
        for index in 0..parameters {
            let name = format!("?{}", index + 1);
            let definition = ColumnDef::text("", "", &name);
            packets
                .write_packet(&response::column_def_payload(&definition))
                .await?;
        }
        if parameters > 0 && self.capabilities & protocol::CLIENT_DEPRECATE_EOF == 0 {
            let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
            packets.write_packet(&eof).await?;
        }
        for definition in &columns {
            packets.write_packet(definition).await?;
        }
        if !columns.is_empty() && self.capabilities & protocol::CLIENT_DEPRECATE_EOF == 0 {
            let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
            packets.write_packet(&eof).await?;
        }
        info!(
            id = self.id,
            statement_id,
            truncated,
            parameters,
            columns = columns.len(),
            sql = %preview(&sql),
            "STMT_PREPARE"
        );
        self.record_query(sql, "PREPARE", "OK(statement)");
        Ok(())
    }

    /// Column definition packets for a prepared statement.
    ///
    /// `COM_STMT_PREPARE_OK` is followed by one definition per result column, so
    /// a `SELECT` has to be resolved at prepare time. Only read-only statements
    /// are evaluated, against a scratch copy of the session state, so `PREPARE
    /// INSERT` can never mutate anything.
    fn prepared_column_payloads(&mut self, sql: &str) -> Vec<Vec<u8>> {
        let kind = fakedb::classify(sql);
        if !matches!(kind, "SELECT" | "SHOW" | "DESCRIBE" | "EXPLAIN") {
            return Vec::new();
        }
        // Cheap bound: a large overlay is not copied for a metadata guess.
        if self.virtual_db.bytes() > 64 * 1024 {
            return Vec::new();
        }
        let mut scratch = self.virtual_db.clone();
        let context = self.context();
        match self.state.database.dispatch(sql, &context, &mut scratch) {
            QueryResult::ResultSet(set) => {
                let mut payloads = Vec::with_capacity(set.columns.len());
                for (index, column) in set.columns.iter().enumerate() {
                    let definition = column_definition(index, column, &set);
                    payloads.push(response::column_def_payload(&definition));
                }
                payloads
            }
            _ => Vec::new(),
        }
    }

    /// `COM_STMT_EXECUTE`: decode the bound parameters, run the stored statement
    /// and answer with a *binary* result set, which is what the client expects
    /// after a prepare.
    async fn execute_prepared(
        &mut self,
        packets: &mut PacketStream<TcpStream>,
        body: &[u8],
    ) -> Result<(), ProtocolError> {
        let Some((statement_id, _)) = split_statement_id(body) else {
            self.write_stmt_error(
                packets,
                1243,
                "Unknown prepared statement handler given to mysqld_stmt_execute",
            )
            .await?;
            return Ok(());
        };
        let Some((sql, param_count, previous_types)) = self
            .prepared
            .iter()
            .find(|statement| statement.id == statement_id)
            .map(|statement| {
                (
                    statement.sql.clone(),
                    statement.param_count,
                    statement.param_types.clone(),
                )
            })
        else {
            self.write_stmt_error(
                packets,
                1243,
                "Unknown prepared statement handler given to mysqld_stmt_execute",
            )
            .await?;
            return Ok(());
        };

        // Decode the typed parameter block. Anything malformed is reported as
        // `ER_WRONG_ARGUMENTS`, exactly like a real server, and never reaches the
        // evaluator.
        let request = match execute::decode_execute(body, param_count, &previous_types) {
            Ok(request) => request,
            Err(err) => {
                if let Some(statement) = self
                    .prepared
                    .iter_mut()
                    .find(|statement| statement.id == statement_id)
                {
                    // A failed execute must not leave the reuse cache poisoned.
                    statement.param_types.clear();
                }
                let payload = response::err_payload(
                    self.capabilities,
                    err.code(),
                    err.sqlstate(),
                    &err.message(),
                );
                packets.write_packet(&payload).await?;
                debug!(id = self.id, code = err.code(), "STMT_EXECUTE refused");
                self.record_query(sql, "EXECUTE", &format!("ERR({})", err.code()));
                return Ok(());
            }
        };
        if request.cursor {
            // Cursors need `COM_STMT_FETCH`, which this server answers with
            // `ER_UNSUPPORTED_PS`; pretending to open one would desynchronise the
            // client, so refuse up front.
            let payload = response::err_payload(
                self.capabilities,
                execute::ER_UNSUPPORTED_PS,
                "HY000",
                "Cursors are not supported in the prepared statement protocol yet",
            );
            packets.write_packet(&payload).await?;
            self.record_query(sql, "EXECUTE", "ERR(cursor unsupported)");
            return Ok(());
        }
        // Remember the types so a later execute may reuse them.
        if let Some(statement) = self
            .prepared
            .iter_mut()
            .find(|statement| statement.id == statement_id)
        {
            statement.param_types = request.param_types.clone();
        }

        self.queries += 1;
        let query_type = fakedb::classify(&sql);
        let context = self.context().with_params(request.values.clone());
        let result = self
            .state
            .database
            .dispatch(&sql, &context, &mut self.virtual_db);
        if self.state.config.logging.log_queries {
            info!(
                id = self.id,
                kind = query_type,
                params = request.values.len(),
                sql = %preview(&sql),
                "EXECUTE"
            );
        }
        // The audit trail records what actually ran: the statement skeleton plus
        // the bound values, rendered as the literals the client sent. The
        // handshake and `COM_CHANGE_USER` authentication responses are never
        // logged; a parameter value is part of the attempted statement exactly
        // like a literal in a plain `COM_QUERY`.
        let audited = if request.values.is_empty() {
            sql
        } else {
            let rendered = fakedb::sql::render_bound_statement(&sql, &request.values);
            clip(&rendered, MAX_AUDIT_SQL_BYTES)
        };
        self.record_query(audited, query_type, &result.kind());
        match result {
            QueryResult::ResultSet(set) => {
                let columns: Vec<ColumnDef<'_>> = set
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| column_definition(index, column, &set))
                    .collect();
                let types: Vec<u8> = set
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| {
                        response::binary_column_type(
                            column.wire_type,
                            set.rows.iter().map(|row| row.get(index).cloned().flatten()),
                        )
                    })
                    .collect();
                response::write_binary_result_set(
                    packets,
                    self.capabilities,
                    &columns,
                    &types,
                    &set.rows,
                    SERVER_STATUS_AUTOCOMMIT,
                )
                .await?;
            }
            other => self.write_result(packets, other).await?,
        }
        Ok(())
    }

    async fn write_field_list(
        &mut self,
        packets: &mut PacketStream<TcpStream>,
        table: &str,
    ) -> Result<(), ProtocolError> {
        let context = self.context();
        let sql = format!("SHOW COLUMNS FROM {}", log_field(table, 64));
        let result = self
            .state
            .database
            .dispatch(&sql, &context, &mut self.virtual_db);
        match result {
            QueryResult::ResultSet(set) if !set.rows.is_empty() => {
                for row in &set.rows {
                    let name = row.first().cloned().flatten().unwrap_or_default();
                    let data_type = row.get(1).cloned().flatten().unwrap_or_default();
                    let mut definition = ColumnDef::text("", table, &name);
                    definition.column_type = fakedb_type_for(&data_type);
                    packets
                        .write_packet(&response::column_def_payload(&definition))
                        .await?;
                }
                let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
                packets.write_packet(&eof).await?;
            }
            QueryResult::ResultSet(_) => {
                let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
                packets.write_packet(&eof).await?;
            }
            QueryResult::Error {
                code,
                sqlstate,
                message,
            } => {
                let payload = response::err_payload(self.capabilities, code, sqlstate, &message);
                packets.write_packet(&payload).await?;
            }
            _ => {
                let eof = response::eof_payload(self.capabilities, 0, SERVER_STATUS_AUTOCOMMIT);
                packets.write_packet(&eof).await?;
            }
        }
        debug!(id = self.id, "FIELD_LIST");
        Ok(())
    }

    /// Write an `ERR` packet for a prepared-statement command.
    async fn write_stmt_error(
        &self,
        packets: &mut PacketStream<TcpStream>,
        code: u16,
        message: &str,
    ) -> Result<(), ProtocolError> {
        let payload = response::err_payload(self.capabilities, code, "HY000", message);
        packets.write_packet(&payload).await
    }

    fn context(&self) -> QueryContext {
        QueryContext::new(
            self.current_db.clone(),
            self.username.clone(),
            self.source_ip.clone(),
            self.id as u32,
            self.state.config.server.version.clone(),
        )
    }

    /// Run one `COM_QUERY` statement and stash its response.
    async fn execute_query(&mut self, raw: &str) -> Result<(), ProtocolError> {
        self.queries += 1;
        let limit = self.state.config.server.max_sql_length;
        let (sql_text, truncated) = util::truncate_to(raw, limit);
        let query_type = fakedb::classify(&sql_text);
        let context = self.context();
        let result = self
            .state
            .database
            .dispatch(&sql_text, &context, &mut self.virtual_db);

        // `USE` changes the session's schema, exactly like a real server.
        if let Some(name) = fakedb::use_target(&sql_text)
            && self.state.database.has_schema(&name, &self.virtual_db)
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
        self.last_result = Some(result);
        Ok(())
    }

    fn record_query(&self, sql_text: String, query_type: &'static str, response_type: &str) {
        self.state.logger.record(Event::Query {
            connection_id: self.id,
            source_ip: self.source_ip.clone(),
            username: log_field(&self.username, LOG_USERNAME_LIMIT),
            sql_text,
            query_type,
            executed_at: util::utc_now(),
            response_type: log_field(response_type, 128),
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
                    .enumerate()
                    .map(|(index, column)| column_definition(index, column, &set))
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

/// Build the wire column definition for one result column.
///
/// Numeric columns advertise the binary charset (63) and a realistic display
/// width, text columns the connection charset and the widest value on the page.
fn column_definition<'a>(
    index: usize,
    column: &'a crate::fakedb::ResultColumn,
    set: &'a crate::fakedb::ResultSet,
) -> ColumnDef<'a> {
    let numeric = matches!(
        column.wire_type,
        crate::protocol::response::column_type::LONGLONG
            | crate::protocol::response::column_type::DOUBLE
            | crate::protocol::response::column_type::LONG
    );
    let (charset, length) = if numeric {
        (63u16, 21u32)
    } else {
        let widest = set
            .rows
            .iter()
            .filter_map(|row| row.get(index))
            .filter_map(|cell| cell.as_ref().map(String::len))
            .max()
            .unwrap_or(0);
        (
            u32::from(CHARSET_UTF8MB4) as u16,
            u32::try_from(widest.max(32)).unwrap_or(TEXT_COLUMN_LENGTH),
        )
    };
    ColumnDef {
        schema: &column.schema,
        table: &column.table,
        org_table: &column.table,
        name: &column.name,
        org_name: &column.org_name,
        charset,
        column_length: length,
        column_type: column.wire_type,
        flags: 0,
        decimals: 0,
    }
}

fn fakedb_type_for(data_type: &str) -> u8 {
    use crate::protocol::response::column_type;
    match data_type.split(['(', ' ']).next().unwrap_or(data_type) {
        "int" | "integer" | "mediumint" | "smallint" | "tinyint" | "bigint" | "bit" => {
            column_type::LONGLONG
        }
        "decimal" | "numeric" | "double" | "float" | "real" => column_type::DOUBLE,
        "date" => column_type::DATE,
        "datetime" | "timestamp" => column_type::DATETIME,
        _ => column_type::VAR_STRING,
    }
}

/// Read the `statement_id` from the start of a statement command payload.
fn split_statement_id(body: &[u8]) -> Option<(u32, usize)> {
    if body.len() < 4 {
        return None;
    }
    let id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    Some((id, 4))
}

/// UTF-8 safe clip for log and database fields.
fn clip(text: &str, max_bytes: usize) -> String {
    util::truncate_to(text, max_bytes).0
}

/// Clip *and* neutralise control characters.
///
/// A username or client attribute full of newlines and ANSI escapes would
/// otherwise let an attacker forge terminal log lines; the audit database keeps
/// the raw bytes because the SQLite writer binds them as parameters.
fn log_field(text: &str, max_bytes: usize) -> String {
    fakedb::sanitise(&clip(text, max_bytes))
}

/// Collapse control characters so a hostile statement cannot forge log lines.
fn preview(sql: &str) -> String {
    log_field(sql, LOG_SQL_PREVIEW)
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
