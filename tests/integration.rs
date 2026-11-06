// SPDX-License-Identifier: GPL-3.0-only
//! Integration tests: a real client speaks to the real listener over TCP.
//!
//! Every test starts its own honeypot on an ephemeral port with its own SQLite
//! file, so nothing is shared between tests and nothing touches port 3306.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use mysql_honeypot_rs::config::Config;
use mysql_honeypot_rs::protocol::packet::{PacketStream, PayloadBuilder, PayloadReader};
use mysql_honeypot_rs::protocol::{
    CLIENT_CONNECT_ATTRS, CLIENT_CONNECT_WITH_DB, CLIENT_DEPRECATE_EOF, CLIENT_PLUGIN_AUTH,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION,
};
use mysql_honeypot_rs::server;
use mysql_honeypot_rs::sqlite_log::SqliteLogger;
use rusqlite::Connection;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

const READ_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct TestHoneypot {
    address: SocketAddr,
    config: Config,
    logger: Arc<SqliteLogger>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestHoneypot {
    async fn start(mut config: Config) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "honeypot-it-{}-{unique}-{}.db",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        config.database.sqlite_path = path.to_string_lossy().into_owned();
        config.database.enable_wal = true;
        config.sanitize();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("local address");
        let logger = Arc::new(SqliteLogger::spawn(&config.database).expect("logger"));
        let (shutdown, receiver) = oneshot::channel();
        let serve_config = config.clone();
        let serve_logger = Arc::clone(&logger);
        let handle = tokio::spawn(async move {
            server::serve(listener, serve_config, serve_logger, async {
                let _ = receiver.await;
            })
            .await
            .expect("serve");
        });

        Self {
            address,
            config,
            logger,
            shutdown: Some(shutdown),
            handle: Some(handle),
        }
    }

    async fn stop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(20), handle).await;
        }
        self.logger.shutdown();
    }

    fn database_path(&self) -> PathBuf {
        PathBuf::from(&self.config.database.sqlite_path)
    }

    fn open_database(&self) -> Connection {
        Connection::open(self.database_path()).expect("open sqlite")
    }

    async fn client(&self) -> Client {
        Client::connect(self.address, "root", None).await
    }

    async fn client_with(&self, username: &str, plugin: Option<&str>) -> Client {
        Client::connect(self.address, username, plugin).await
    }

    fn cleanup(&self) {
        let path = self.database_path();
        let _ = std::fs::remove_file(&path);
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}

fn base_config() -> Config {
    let mut config = Config::default();
    // Keep the suite fast; one dedicated test exercises the real default window.
    config.authentication.delay_min_ms = 60;
    config.authentication.delay_max_ms = 90;
    config.server.max_connections = 32;
    config.server.max_sql_length = 512;
    config.logging.level = "info".to_string();
    config
}

/// What a client got back for one command.
#[derive(Debug)]
enum Response {
    Ok {
        affected_rows: u64,
    },
    Err {
        code: u16,
        sqlstate: String,
        message: String,
    },
    ResultSet {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Eof,
}

impl Response {
    fn expect_result(self) -> (Vec<String>, Vec<Vec<String>>) {
        match self {
            Self::ResultSet { columns, rows } => (columns, rows),
            other => panic!("expected a result set, got {other:?}"),
        }
    }

    fn expect_ok(self) -> u64 {
        match self {
            Self::Ok { affected_rows } => affected_rows,
            other => panic!("expected OK, got {other:?}"),
        }
    }
}

struct Client {
    packets: PacketStream<TcpStream>,
    capabilities: u32,
    greeting_version: String,
    auth_delay: Duration,
}

impl Client {
    async fn connect(address: SocketAddr, username: &str, plugin: Option<&str>) -> Self {
        Self::connect_with(address, username, plugin, None, false).await
    }

    async fn connect_with(
        address: SocketAddr,
        username: &str,
        plugin: Option<&str>,
        database: Option<&str>,
        deprecate_eof: bool,
    ) -> Self {
        let stream = tokio::time::timeout(READ_TIMEOUT, TcpStream::connect(address))
            .await
            .expect("connect timeout")
            .expect("connect");
        stream.set_nodelay(true).expect("nodelay");
        let mut packets = PacketStream::new(stream, 1 << 20);

        // ---- greeting ----------------------------------------------------
        let greeting = tokio::time::timeout(READ_TIMEOUT, packets.read_packet())
            .await
            .expect("greeting timeout")
            .expect("greeting");
        let mut reader = PayloadReader::new(&greeting);
        let protocol_version = reader.u8().expect("protocol version");
        assert_eq!(
            protocol_version, 10,
            "server must speak protocol version 10"
        );
        let greeting_version = reader.nul_str().expect("server version");
        let _connection_id = reader.u32le().expect("connection id");
        let _salt_part_one = reader.take(8).expect("salt 1");
        let _filler = reader.u8().expect("filler");
        let capabilities_low = u32::from(reader.u16le().expect("caps low"));
        let _charset = reader.u8().expect("charset");
        let _status = reader.u16le().expect("status");
        let capabilities_high = u32::from(reader.u16le().expect("caps high"));
        let server_capabilities = capabilities_low | (capabilities_high << 16);
        assert_ne!(
            server_capabilities & CLIENT_PROTOCOL_41,
            0,
            "server must advertise CLIENT_PROTOCOL_41"
        );
        assert_eq!(
            server_capabilities & 0x0000_0800,
            0,
            "server must not advertise CLIENT_SSL"
        );

        // ---- handshake response -------------------------------------------
        let mut capabilities = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            | CLIENT_CONNECT_ATTRS;
        if database.is_some() {
            capabilities |= CLIENT_CONNECT_WITH_DB;
        }
        if deprecate_eof {
            capabilities |= CLIENT_DEPRECATE_EOF;
        }
        capabilities &= server_capabilities | CLIENT_CONNECT_ATTRS;

        let mut payload = PayloadBuilder::new();
        payload
            .u32le(capabilities)
            .u32le(16 * 1024 * 1024)
            .u8(45)
            .zeros(23)
            .nul_str(username)
            .lenenc_int(32)
            .bytes(&[0x5a; 32]);
        if let Some(name) = database {
            payload.nul_str(name);
        }
        if let Some(name) = plugin {
            payload.nul_str(name);
        }
        // connect attributes
        let mut attributes = PayloadBuilder::new();
        attributes
            .lenenc_str("_client_name")
            .lenenc_str("integration-test")
            .lenenc_str("_os")
            .lenenc_str("test");
        let attributes = attributes.into_vec();
        payload
            .lenenc_int(attributes.len() as u64)
            .bytes(&attributes);

        let sent_at = Instant::now();
        packets.set_sequence(1);
        packets
            .write_packet(&payload.into_vec())
            .await
            .expect("handshake response");

        // ---- authentication ------------------------------------------------
        let first = tokio::time::timeout(READ_TIMEOUT, packets.read_packet())
            .await
            .expect("auth timeout")
            .expect("auth packet");
        let mut final_packet = first;
        if final_packet[0] == 0x01 {
            // AuthMoreData: caching_sha2_password fast path.
            assert_eq!(
                final_packet.get(1),
                Some(&0x03),
                "expected the fast-auth-success marker"
            );
            final_packet = tokio::time::timeout(READ_TIMEOUT, packets.read_packet())
                .await
                .expect("ok timeout")
                .expect("ok packet");
        }
        let auth_delay = sent_at.elapsed();
        match final_packet[0] {
            0x00 => {}
            0xff => {
                let mut reader = PayloadReader::new(&final_packet);
                reader.u8().expect("header");
                let code = reader.u16le().expect("code");
                panic!("authentication refused with error {code}");
            }
            other => panic!("unexpected auth packet header {other:#04x}"),
        }

        Self {
            packets,
            capabilities,
            greeting_version,
            auth_delay,
        }
    }

    async fn send_raw(&mut self, payload: &[u8]) {
        self.packets.set_sequence(0);
        self.packets
            .write_packet(payload)
            .await
            .expect("write raw command");
    }

    async fn query(&mut self, sql: &str) -> Response {
        self.send_raw(&command(0x03, sql.as_bytes())).await;
        self.read_response().await
    }

    async fn send_command(&mut self, command_byte: u8, body: &[u8]) -> Response {
        self.send_raw(&command(command_byte, body)).await;
        self.read_response().await
    }

    async fn read_response(&mut self) -> Response {
        let first = tokio::time::timeout(READ_TIMEOUT, self.packets.read_packet())
            .await
            .expect("response timeout")
            .expect("response packet");
        if first.is_empty() {
            return Response::Eof;
        }
        match first[0] {
            0x00 => {
                let mut reader = PayloadReader::new(&first);
                reader.u8().expect("header");
                let affected_rows = reader.lenenc_int().expect("affected").unwrap_or(0);
                Response::Ok { affected_rows }
            }
            0xff => {
                let mut reader = PayloadReader::new(&first);
                reader.u8().expect("header");
                let code = reader.u16le().expect("code");
                let mut sqlstate = String::new();
                if !reader.is_empty() {
                    let marker = reader.u8().expect("marker");
                    if marker == b'#' {
                        sqlstate =
                            String::from_utf8_lossy(reader.take(5).expect("state")).into_owned();
                    }
                }
                let message = String::from_utf8_lossy(reader.rest()).into_owned();
                Response::Err {
                    code,
                    sqlstate,
                    message,
                }
            }
            0xfe if first.len() < 9 => Response::Eof,
            _ => self.read_result_set(&first).await,
        }
    }

    async fn read_result_set(&mut self, header: &[u8]) -> Response {
        let mut reader = PayloadReader::new(header);
        let count = reader.lenenc_int().expect("column count").unwrap_or(0) as usize;
        let mut columns = Vec::with_capacity(count);
        for _ in 0..count {
            let definition = self.read_packet().await;
            let mut reader = PayloadReader::new(&definition);
            let _catalog = reader.lenenc_str().expect("catalog");
            let _schema = reader.lenenc_str().expect("schema");
            let _table = reader.lenenc_str().expect("table");
            let _org_table = reader.lenenc_str().expect("org table");
            let name = reader.lenenc_str().expect("name").unwrap_or_default();
            let _org_name = reader.lenenc_str().expect("org name");
            let _fixed = reader.lenenc_int().expect("fixed length");
            columns.push(name);
        }
        if self.capabilities & CLIENT_DEPRECATE_EOF == 0 {
            let separator = self.read_packet().await;
            assert_eq!(separator[0], 0xfe, "classic EOF after column definitions");
        }
        let mut rows = Vec::new();
        loop {
            let packet = self.read_packet().await;
            if packet.is_empty() {
                continue;
            }
            if packet[0] == 0xfe && packet.len() < 9 {
                break;
            }
            let mut reader = PayloadReader::new(&packet);
            let mut values = Vec::new();
            while !reader.is_empty() {
                values.push(reader.lenenc_str().expect("value").unwrap_or_default());
            }
            rows.push(values);
        }
        Response::ResultSet { columns, rows }
    }

    async fn read_packet(&mut self) -> Vec<u8> {
        tokio::time::timeout(READ_TIMEOUT, self.packets.read_packet())
            .await
            .expect("packet timeout")
            .expect("packet")
    }

    /// `COM_STMT_PREPARE` + `COM_STMT_EXECUTE` + `COM_STMT_CLOSE`.
    ///
    /// The server answers `EXECUTE` with a *binary* result set, so the response
    /// is decoded with the binary row layout rather than the text one.
    async fn binary_query(&mut self, sql: &str) -> Response {
        self.send_raw(&command(0x16, sql.as_bytes())).await;
        let prepare = self.read_packet().await;
        assert_eq!(
            prepare[0], 0x00,
            "COM_STMT_PREPARE must answer with COM_STMT_PREPARE_OK, got {prepare:?}"
        );
        let mut reader = PayloadReader::new(&prepare);
        reader.u8().expect("header");
        let statement_id = reader.u32le().expect("statement id");
        let columns = reader.u16le().expect("column count");
        let parameters = reader.u16le().expect("parameter count");
        // Parameter definitions, then result column definitions, each block
        // closed by an EOF unless CLIENT_DEPRECATE_EOF was negotiated.
        for _ in 0..parameters {
            let _ = self.read_packet().await;
        }
        if parameters > 0 && self.capabilities & CLIENT_DEPRECATE_EOF == 0 {
            assert_eq!(self.read_packet().await[0], 0xfe);
        }
        for _ in 0..columns {
            let _ = self.read_packet().await;
        }
        if columns > 0 && self.capabilities & CLIENT_DEPRECATE_EOF == 0 {
            assert_eq!(self.read_packet().await[0], 0xfe);
        }

        let mut execute = command(0x17, &statement_id.to_le_bytes());
        // flags, iteration count, and a null bitmap for the (unused) parameters.
        execute.push(0x00);
        execute.extend_from_slice(&1u32.to_le_bytes());
        self.send_raw(&execute).await;
        let response = self.read_binary_response().await;

        // COM_STMT_CLOSE expects no reply.
        self.send_raw(&command(0x19, &statement_id.to_le_bytes()))
            .await;
        response
    }

    async fn read_binary_response(&mut self) -> Response {
        let first = self.read_packet().await;
        if first.is_empty() {
            return Response::Eof;
        }
        match first[0] {
            0x00 => {
                let mut reader = PayloadReader::new(&first);
                reader.u8().expect("header");
                let affected_rows = reader.lenenc_int().expect("affected").unwrap_or(0);
                Response::Ok { affected_rows }
            }
            0xff => {
                let mut reader = PayloadReader::new(&first);
                reader.u8().expect("header");
                let code = reader.u16le().expect("code");
                let mut sqlstate = String::new();
                if !reader.is_empty() {
                    let marker = reader.u8().expect("marker");
                    if marker == b'#' {
                        sqlstate =
                            String::from_utf8_lossy(reader.take(5).expect("state")).into_owned();
                    }
                }
                let message = String::from_utf8_lossy(reader.rest()).into_owned();
                Response::Err {
                    code,
                    sqlstate,
                    message,
                }
            }
            _ => {
                let mut reader = PayloadReader::new(&first);
                let count = reader.lenenc_int().expect("column count").unwrap_or(0) as usize;
                let mut names = Vec::with_capacity(count);
                let mut types = Vec::with_capacity(count);
                for _ in 0..count {
                    let definition = self.read_packet().await;
                    let mut reader = PayloadReader::new(&definition);
                    let _catalog = reader.lenenc_str().expect("catalog");
                    let _schema = reader.lenenc_str().expect("schema");
                    let _table = reader.lenenc_str().expect("table");
                    let _org_table = reader.lenenc_str().expect("org table");
                    let name = reader.lenenc_str().expect("name").unwrap_or_default();
                    let _org_name = reader.lenenc_str().expect("org name");
                    let _fixed = reader.lenenc_int().expect("fixed length");
                    let _charset = reader.u16le().expect("charset");
                    let _length = reader.u32le().expect("length");
                    let wire_type = reader.u8().expect("column type");
                    names.push(name);
                    types.push(wire_type);
                }
                if self.capabilities & CLIENT_DEPRECATE_EOF == 0 {
                    assert_eq!(self.read_packet().await[0], 0xfe);
                }
                let mut rows = Vec::new();
                loop {
                    let packet = self.read_packet().await;
                    if packet.is_empty() {
                        continue;
                    }
                    if packet[0] == 0xfe && packet.len() < 9 {
                        break;
                    }
                    assert_eq!(packet[0], 0x00, "binary row header");
                    let bitmap_len = (count + 7 + 2) / 8;
                    let bitmap = &packet[1..1 + bitmap_len];
                    let mut reader = PayloadReader::new(&packet[1 + bitmap_len..]);
                    let mut values = Vec::with_capacity(count);
                    for index in 0..count {
                        let position = index + 2;
                        let is_null = bitmap[position / 8] & (1 << (position % 8)) != 0;
                        if is_null {
                            values.push(String::new());
                            continue;
                        }
                        // Numeric columns are re-typed at execute time, so the
                        // binary payload is decoded per the definition we just
                        // read rather than assumed to be text.
                        let value = match types.get(index).copied().unwrap_or(0xfd) {
                            0x08 => {
                                let raw = reader.take(8).expect("int64");
                                let mut bytes = [0u8; 8];
                                bytes.copy_from_slice(raw);
                                i64::from_le_bytes(bytes).to_string()
                            }
                            0x05 => {
                                let raw = reader.take(8).expect("float64");
                                let mut bytes = [0u8; 8];
                                bytes.copy_from_slice(raw);
                                f64::from_le_bytes(bytes).to_string()
                            }
                            _ => reader.lenenc_str().expect("value").unwrap_or_default(),
                        };
                        values.push(value);
                    }
                    rows.push(values);
                }
                Response::ResultSet {
                    columns: names,
                    rows,
                }
            }
        }
    }

    /// `COM_STMT_PREPARE`, returning `(statement_id, parameter count)`.
    async fn prepare(&mut self, sql: &str) -> (u32, u16) {
        self.send_raw(&command(0x16, sql.as_bytes())).await;
        let prepare = self.read_packet().await;
        assert_eq!(
            prepare[0], 0x00,
            "COM_STMT_PREPARE must answer with COM_STMT_PREPARE_OK, got {prepare:?}"
        );
        let mut reader = PayloadReader::new(&prepare);
        reader.u8().expect("header");
        let statement_id = reader.u32le().expect("statement id");
        let columns = reader.u16le().expect("column count");
        let parameters = reader.u16le().expect("parameter count");
        for _ in 0..parameters {
            let _ = self.read_packet().await;
        }
        if parameters > 0 && self.capabilities & CLIENT_DEPRECATE_EOF == 0 {
            assert_eq!(self.read_packet().await[0], 0xfe);
        }
        for _ in 0..columns {
            let _ = self.read_packet().await;
        }
        if columns > 0 && self.capabilities & CLIENT_DEPRECATE_EOF == 0 {
            assert_eq!(self.read_packet().await[0], 0xfe);
        }
        (statement_id, parameters)
    }

    /// `COM_STMT_EXECUTE` with a real parameter block.
    ///
    /// `send_types` maps to `new_params_bound_flag`: when it is `false` the
    /// server has to reuse the types from the previous execute.
    async fn execute(&mut self, statement_id: u32, params: &[Param], send_types: bool) -> Response {
        self.execute_raw(&execute_payload(statement_id, params, send_types, 0x00, 1))
            .await
    }

    /// `COM_STMT_EXECUTE` straight from a payload, for hostile-packet tests.
    async fn execute_raw(&mut self, body: &[u8]) -> Response {
        self.send_raw(&command(0x17, body)).await;
        self.read_binary_response().await
    }

    /// `COM_STMT_RESET`; answers OK.
    async fn reset_statement(&mut self, statement_id: u32) {
        self.send_raw(&command(0x1a, &statement_id.to_le_bytes()))
            .await;
        let response = self.read_packet().await;
        assert_eq!(response[0], 0x00, "COM_STMT_RESET must answer OK");
    }

    /// `COM_STMT_CLOSE` expects no reply.
    async fn close_statement(&mut self, statement_id: u32) {
        self.send_raw(&command(0x19, &statement_id.to_le_bytes()))
            .await;
    }
}

/// Build a `COM_STMT_EXECUTE` body.
fn execute_payload(
    statement_id: u32,
    params: &[Param],
    send_types: bool,
    flags: u8,
    iteration_count: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&statement_id.to_le_bytes());
    body.push(flags);
    body.extend_from_slice(&iteration_count.to_le_bytes());
    if !params.is_empty() {
        let mut bitmap = vec![0u8; params.len().div_ceil(8)];
        for (index, param) in params.iter().enumerate() {
            if matches!(param, Param::Null) {
                bitmap[index / 8] |= 1 << (index % 8);
            }
        }
        body.extend_from_slice(&bitmap);
        body.push(u8::from(send_types));
        if send_types {
            for param in params {
                let (wire, unsigned) = param.wire_type();
                body.push(wire);
                body.push(unsigned);
            }
        }
        for param in params {
            param.encode(&mut body);
        }
    }
    body
}

/// One bound parameter for `COM_STMT_EXECUTE`, with the wire type it is sent as.
#[derive(Debug, Clone, PartialEq)]
enum Param {
    /// `MYSQL_TYPE_LONGLONG`
    Int(i64),
    /// `MYSQL_TYPE_DOUBLE`
    Double(f64),
    /// `MYSQL_TYPE_VAR_STRING`
    Str(String),
    /// `MYSQL_TYPE_NULL`, also flagged in the NULL bitmap
    Null,
}

impl Param {
    fn wire_type(&self) -> (u8, u8) {
        match self {
            Self::Int(_) => (0x08, 0),
            Self::Double(_) => (0x05, 0),
            Self::Str(_) => (0xfd, 0),
            Self::Null => (0x06, 0),
        }
    }

    fn encode(&self, body: &mut Vec<u8>) {
        match self {
            Self::Int(value) => body.extend_from_slice(&value.to_le_bytes()),
            Self::Double(value) => body.extend_from_slice(&value.to_le_bytes()),
            Self::Str(text) => {
                body.push(text.len() as u8);
                body.extend_from_slice(text.as_bytes());
            }
            Self::Null => {}
        }
    }
}

fn command(command_byte: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(body.len() + 1);
    payload.push(command_byte);
    payload.extend_from_slice(body);
    payload
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn any_credentials_are_accepted() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    for (username, plugin) in [
        ("root", Some("caching_sha2_password")),
        ("admin", Some("mysql_native_password")),
        ("test", Some("caching_sha2_password")),
        ("weird'user\"with\\quotes", None),
    ] {
        let mut client = honeypot.client_with(username, plugin).await;
        assert_eq!(
            client.query("SELECT 1").await.expect_ok_or_rows(),
            1,
            "session for {username} must be usable"
        );
        assert!(
            !client.greeting_version.is_empty(),
            "greeting must carry a version"
        );
    }
    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_delay_uses_the_configured_window() {
    // Defaults: 2000..=6000 ms. This is the one slow test.
    let config = Config::default();
    let mut honeypot = TestHoneypot::start(config).await;
    let client = honeypot.client().await;
    let measured = client.auth_delay.as_millis();
    assert!(
        (2_000..=6_600).contains(&measured),
        "authentication delay {measured}ms outside the 2000..6000 window"
    );

    // A second login must draw its own independent delay.
    let other = honeypot.client().await;
    let second = other.auth_delay.as_millis();
    assert!(
        (2_000..=6_600).contains(&second),
        "second delay {second}ms outside the window"
    );
    honeypot.stop().await;

    let database = honeypot.open_database();
    let delays: Vec<i64> = database
        .prepare("SELECT auth_delay_ms FROM connections ORDER BY id")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("rows")
        .filter_map(std::result::Result::ok)
        .collect();
    assert_eq!(delays.len(), 2, "both logins must be recorded");
    for delay in delays {
        assert!(
            (2_000..=6_600).contains(&delay),
            "recorded delay {delay} outside the window"
        );
    }
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn show_databases_and_select_one() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (columns, rows) = client.query("SHOW DATABASES").await.expect_result();
    assert_eq!(columns, vec!["Database".to_string()]);
    let names: Vec<String> = rows.into_iter().map(|row| row[0].clone()).collect();
    for expected in [
        "information_schema",
        "mysql",
        "performance_schema",
        "sys",
        "app_prod",
        "backup",
    ] {
        assert!(names.contains(&expected.to_string()), "missing {expected}");
    }

    let (columns, rows) = client.query("SELECT 1").await.expect_result();
    assert_eq!(columns.len(), 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], "1");

    let (_, rows) = client.query("SELECT VERSION()").await.expect_result();
    assert_eq!(rows[0][0], honeypot.config.server.version);

    let (_, rows) = client.query("SELECT USER()").await.expect_result();
    assert!(rows[0][0].starts_with("root@"));

    let (_, rows) = client.query("SELECT DATABASE()").await.expect_result();
    assert_eq!(rows[0][0], "");

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_survives_a_long_statement_stream() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let statements = [
        "SELECT 1",
        "USE mysql",
        "SHOW TABLES",
        "SHOW VARIABLES LIKE 'version%'",
        "SELECT @@version",
        "DESCRIBE user",
        "CREATE TABLE evil (id int)",
        "INSERT INTO evil VALUES (1)",
        "UPDATE evil SET id = 2",
        "DELETE FROM evil",
        "DROP TABLE evil",
        "EXPLAIN SELECT * FROM users",
        "SELECT * FROM information_schema.tables WHERE table_schema = 'app_prod'",
        "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE users",
        "not sql at all",
        "SELECT 1",
    ];
    for (index, statement) in statements.iter().enumerate() {
        let response = client.query(statement).await;
        assert!(
            !matches!(response, Response::Eof),
            "statement {index} ({statement}) got an unexpected EOF"
        );
    }

    // Still alive after all of the above, including two error responses.
    let (_, rows) = client.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");

    honeypot.stop().await;
    let database = honeypot.open_database();
    let count: i64 = database
        .query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))
        .expect("count");
    assert_eq!(
        count as usize,
        statements.len() + 1,
        "every statement must be persisted"
    );
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_records_identity_and_every_statement() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot
        .client_with("attacker", Some("caching_sha2_password"))
        .await;
    client.query("SHOW DATABASES").await;
    client.query("SELECT 1").await;
    client.query("SELECT @@version").await;
    client.query("DROP TABLE users").await;
    honeypot.stop().await;

    let database = honeypot.open_database();
    let (ip, port, username, delay, capabilities, client_info, authenticated): (
        String,
        i64,
        String,
        i64,
        i64,
        String,
        String,
    ) = database
        .query_row(
            "SELECT source_ip, source_port, username, auth_delay_ms, client_capabilities, \
             client_version_info, authenticated_at FROM connections ORDER BY id DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .expect("connection row");
    assert_eq!(ip, "127.0.0.1");
    assert!(port > 0);
    assert_eq!(username, "attacker");
    assert!(delay > 0, "the delay must be recorded");
    assert!(capabilities > 0);
    assert!(
        client_info.contains("_client_name=integration-test"),
        "client attributes must be captured, got {client_info}"
    );
    assert!(authenticated.ends_with('Z'), "timestamps are UTC ISO-8601");

    let mut statement = database
        .prepare("SELECT sql_text, query_type, response_type FROM queries ORDER BY id")
        .expect("prepare");
    let rows: Vec<(String, String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("rows")
        .filter_map(std::result::Result::ok)
        .collect();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].0, "SHOW DATABASES");
    assert_eq!(rows[0].1, "SHOW");
    assert!(rows[0].2.starts_with("RESULTSET"));
    assert_eq!(rows[1].1, "SELECT");
    assert_eq!(rows[2].0, "SELECT @@version");
    assert_eq!(rows[3].1, "DROP");
    assert!(rows[3].2.starts_with("OK"));
    drop(statement);

    let disconnected: Option<String> = database
        .query_row(
            "SELECT disconnected_at FROM connections LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("row");
    assert!(disconnected.is_some(), "disconnect must be recorded");
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_packets_do_not_take_the_server_down() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let address = honeypot.address;

    // (a) pure garbage, no greeting read at all
    {
        use tokio::io::AsyncWriteExt;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream.write_all(&[0x41; 200]).await.expect("write garbage");
        let _ = stream.shutdown().await;
    }
    // (b) a header claiming 16 MiB but almost no body
    {
        use tokio::io::AsyncWriteExt;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(&[0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03])
            .await
            .expect("write oversized header");
        let _ = stream.shutdown().await;
    }
    // (c) only four bytes of a header, then close
    {
        use tokio::io::AsyncWriteExt;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(&[0x10, 0x00, 0x00, 0x00])
            .await
            .expect("write");
        let _ = stream.shutdown().await;
    }
    // (d) a truncated handshake response
    {
        let stream = TcpStream::connect(address).await.expect("connect");
        let mut packets = PacketStream::new(stream, 1 << 20);
        let _greeting = packets.read_packet().await.expect("greeting");
        packets.set_sequence(1);
        packets
            .write_packet(&[0x01, 0x02, 0x03])
            .await
            .expect("write");
    }
    // (e) an unknown command on an authenticated session
    {
        let mut client = honeypot.client().await;
        let response = client.send_command(0x7f, b"").await;
        match response {
            Response::Err {
                code,
                sqlstate,
                message,
            } => {
                assert_eq!(code, 1047);
                assert_eq!(sqlstate, "08S01");
                assert!(!message.is_empty());
            }
            other => panic!("expected unknown-command error, got {other:?}"),
        }
        // The session must still work after the error.
        let (_, rows) = client.query("SELECT 1").await.expect_result();
        assert_eq!(rows[0][0], "1");
    }

    // The process is still serving.
    let mut client = honeypot.client().await;
    let (_, rows) = client.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");
    assert_eq!(honeypot.logger.stats().failed, 0);

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn concurrent_clients_do_not_block_each_other() {
    let mut config = base_config();
    config.authentication.delay_min_ms = 500;
    config.authentication.delay_max_ms = 600;
    let mut honeypot = TestHoneypot::start(config).await;
    let address = honeypot.address;

    let started = Instant::now();
    let mut tasks = Vec::new();
    for index in 0..6 {
        tasks.push(tokio::spawn(async move {
            let mut client = Client::connect(address, &format!("user{index}"), None).await;
            let (_, rows) = client.query("SELECT 1").await.expect_result();
            assert_eq!(rows[0][0], "1");
            client.auth_delay
        }));
    }
    let mut delays = Vec::new();
    for task in tasks {
        delays.push(task.await.expect("client task"));
    }
    let elapsed = started.elapsed();

    // Six logins of >=500ms each would need >=3s if they serialised.
    assert!(
        elapsed < Duration::from_millis(2_500),
        "concurrent logins took {elapsed:?} — the delay must not serialise"
    );
    for delay in delays {
        assert!(
            delay >= Duration::from_millis(450),
            "delay {delay:?} too short"
        );
    }

    honeypot.stop().await;
    let database = honeypot.open_database();
    let count: i64 = database
        .query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 6, "every concurrent session must be logged");
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_limit_is_enforced_with_an_err_packet() {
    let mut config = base_config();
    config.server.max_connections = 1;
    let mut honeypot = TestHoneypot::start(config).await;

    // Hold the only slot by finishing the handshake and staying connected.
    let mut first = honeypot.client().await;
    let (_, rows) = first.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");

    // The next TCP connection is refused before any greeting.
    let stream = TcpStream::connect(honeypot.address).await.expect("connect");
    let mut packets = PacketStream::new(stream, 1 << 20);
    let refusal = packets.read_packet().await.expect("refusal packet");
    assert_eq!(refusal[0], 0xff, "expected an ERR packet");
    let mut reader = PayloadReader::new(&refusal);
    assert_eq!(reader.u8().expect("header"), 0xff);
    assert_eq!(reader.u16le().expect("code"), 1040);

    // The first session is unaffected.
    let (_, rows) = first.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");
    drop(first);

    // Once the slot is released a new client is served normally.
    let mut third = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let attempt = tokio::time::timeout(
            Duration::from_secs(3),
            Client::connect(honeypot.address, "root", None),
        )
        .await;
        if let Ok(client) = attempt {
            third = Some(client);
            break;
        }
    }
    let mut third = third.expect("a slot must free up");
    let (_, rows) = third.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deprecate_eof_and_native_password_paths() {
    let mut honeypot = TestHoneypot::start(base_config()).await;

    // CLIENT_DEPRECATE_EOF: no EOF after the column definitions.
    let client = Client::connect_with(
        honeypot.address,
        "root",
        Some("caching_sha2_password"),
        Some("app_prod"),
        true,
    )
    .await;
    assert_ne!(client.capabilities & CLIENT_DEPRECATE_EOF, 0);
    let mut client = client;
    let (columns, rows) = client.query("SHOW DATABASES").await.expect_result();
    assert_eq!(columns.len(), 1);
    assert_eq!(rows.len(), 6);

    // mysql_native_password: an OK packet with no AuthMoreData frame.
    let mut native = honeypot
        .client_with("legacy", Some("mysql_native_password"))
        .await;
    let (_, rows) = native.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ping_init_db_and_quit_are_handled() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    assert_eq!(
        client.send_command(0x0e, b"").await.expect_ok(),
        0,
        "COM_PING"
    );

    assert_eq!(
        client.send_command(0x02, b"mysql").await.expect_ok(),
        0,
        "COM_INIT_DB on a known schema"
    );
    let (_, rows) = client.query("SELECT DATABASE()").await.expect_result();
    assert_eq!(rows[0][0], "mysql");

    match client.send_command(0x02, b"does_not_exist").await {
        Response::Err {
            code,
            sqlstate,
            message,
        } => {
            assert_eq!(code, 1049);
            assert_eq!(sqlstate, "42000");
            assert!(
                message.contains("Unknown database"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected unknown database error, got {other:?}"),
    }

    // COM_QUIT is fire-and-forget: the server answers only by closing.
    client.send_raw(&command(0x01, b"")).await;
    // COM_QUIT gets no reply; the socket closes.
    let next = tokio::time::timeout(Duration::from_secs(5), client.packets.read_packet()).await;
    match next {
        Ok(Err(_)) => {}
        Ok(Ok(payload)) => panic!("expected the connection to close, got {payload:?}"),
        Err(_) => panic!("server did not close the connection after COM_QUIT"),
    }

    honeypot.stop().await;
    let database = honeypot.open_database();
    let count: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM queries WHERE query_type = 'USE'",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(count, 2, "both COM_INIT_DB attempts must be logged");
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_statements_are_truncated_but_answered() {
    let mut config = base_config();
    config.server.max_sql_length = 64;
    let mut honeypot = TestHoneypot::start(config).await;
    let mut client = honeypot.client().await;

    let long = format!("SELECT 1 /* {} */", "A".repeat(4_000));
    let response = client.query(&long).await;
    assert!(matches!(response, Response::ResultSet { .. }));

    honeypot.stop().await;
    let database = honeypot.open_database();
    let stored: String = database
        .query_row(
            "SELECT sql_text FROM queries ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("row");
    assert_eq!(
        stored.len(),
        64,
        "the statement must be clipped to 64 bytes"
    );
    assert!(stored.is_char_boundary(stored.len()));
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logs_survive_a_restart() {
    let config = base_config();
    let path;
    {
        let mut honeypot = TestHoneypot::start(config.clone()).await;
        path = honeypot.database_path();
        let mut client = honeypot.client().await;
        client.query("SHOW DATABASES").await;
        honeypot.stop().await;
    }
    let first: i64 = {
        let database = Connection::open(&path).expect("open");
        database
            .query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))
            .expect("count")
    };
    {
        // Second run against the same SQLite file.
        let mut config = config;
        config.database.sqlite_path = path.to_string_lossy().into_owned();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let logger = Arc::new(SqliteLogger::spawn(&config.database).expect("logger"));
        let (shutdown, receiver) = oneshot::channel();
        let handle = tokio::spawn({
            let config = config.clone();
            let logger = Arc::clone(&logger);
            async move {
                server::serve(listener, config, logger, async {
                    let _ = receiver.await;
                })
                .await
                .expect("serve");
            }
        });
        // address captured before the listener was moved into the task
        let mut client = Client::connect(address, "second", None).await;
        client.query("SELECT 1").await;
        let _ = shutdown.send(());
        let _ = tokio::time::timeout(Duration::from_secs(20), handle).await;
        logger.shutdown();
    }
    let database = Connection::open(&path).expect("open");
    let count: i64 = database
        .query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, first + 1, "the old rows must survive the restart");
    let users: Vec<String> = database
        .prepare("SELECT username FROM connections ORDER BY id")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("rows")
        .filter_map(std::result::Result::ok)
        .collect();
    assert_eq!(users, vec!["root".to_string(), "second".to_string()]);
    drop(database);
    let _ = std::fs::remove_file(&path);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_sessions_are_closed_and_recorded() {
    // `idle_timeout_seconds` is clamped to a minimum of 5 s, so this is the one
    // slow test besides the default-delay one.
    let mut config = base_config();
    config.server.idle_timeout_seconds = 5;
    let mut honeypot = TestHoneypot::start(config).await;
    let mut client = honeypot.client().await;
    let (_, rows) = client.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");

    // Say nothing for longer than the idle timeout: the server must hang up.
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(15), client.packets.read_packet()).await;
    let waited = started.elapsed();
    match outcome {
        Ok(Err(_)) => {}
        Ok(Ok(payload)) => panic!("expected the idle session to be closed, got {payload:?}"),
        Err(_) => panic!("server did not close the idle session within 15s"),
    }
    assert!(
        (Duration::from_secs(4)..Duration::from_secs(12)).contains(&waited),
        "idle close after {waited:?} does not match the 5s timeout"
    );

    honeypot.stop().await;
    let database = honeypot.open_database();
    let (disconnected, duration): (Option<String>, Option<i64>) = database
        .query_row(
            "SELECT disconnected_at, duration_ms FROM connections LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("connection row");
    assert!(
        disconnected.is_some(),
        "an idle-closed session must still be recorded as disconnected"
    );
    assert!(duration.unwrap_or(0) >= 4_000);
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_garbage_never_kills_the_server() {
    // Deterministic xorshift so a failure is reproducible from the seed.
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };

    let mut config = base_config();
    config.server.max_connections = 128;
    let mut honeypot = TestHoneypot::start(config).await;
    let address = honeypot.address;

    for round in 0..120u32 {
        use tokio::io::AsyncWriteExt;
        let stream = TcpStream::connect(address).await.expect("connect");
        let _ = stream.set_nodelay(true);
        let mut bytes: Vec<u8> = Vec::new();
        match round % 4 {
            // Pure noise, no valid frame at all.
            0 => {
                let len = 1 + (next() % 64) as usize;
                for _ in 0..len {
                    bytes.push((next() & 0xff) as u8);
                }
            }
            // A plausible header declaring far more than is sent.
            1 => {
                let declared = (next() % 0x2000) as u32;
                bytes.extend_from_slice(&declared.to_le_bytes()[..3]);
                bytes.push((next() & 0xff) as u8);
                for _ in 0..(next() % 16) {
                    bytes.push((next() & 0xff) as u8);
                }
            }
            // Continuation-frame flood: claims a 16 MiB payload.
            2 => bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0x00]),
            // Repeated 8-byte length-encoded markers.
            _ => {
                let count = (next() % 32) as usize;
                bytes.resize(bytes.len() + count, 0xfe);
            }
        }
        let _ = stream.writable().await;
        let mut stream = stream;
        let _ = stream.write_all(&bytes).await;
        let _ = stream.shutdown().await;
        drop(stream);

        if round % 30 == 0 {
            // The listener must keep answering while the storm is running.
            let mut client = honeypot.client().await;
            let (_, rows) = client.query("SELECT 1").await.expect_result();
            assert_eq!(rows[0][0], "1", "round {round}: server stopped answering");
        }
    }

    // And after it.
    let mut client = honeypot.client().await;
    let (_, rows) = client.query("SHOW DATABASES").await.expect_result();
    assert_eq!(rows.len(), 6);
    assert_eq!(
        honeypot.logger.stats().failed,
        0,
        "no log event may be lost while fuzzing"
    );

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_clients_are_dropped_after_the_handshake_timeout() {
    let mut config = base_config();
    config.server.handshake_timeout_seconds = 1;
    let mut honeypot = TestHoneypot::start(config).await;

    // Connect, read the greeting, then say nothing at all.
    let stream = TcpStream::connect(honeypot.address).await.expect("connect");
    let mut packets = PacketStream::new(stream, 1 << 20);
    let _greeting = packets.read_packet().await.expect("greeting");
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(10), packets.read_packet()).await;
    match outcome {
        Ok(Err(_)) => {}
        Ok(Ok(payload)) => panic!("expected a hang-up, got {payload:?}"),
        Err(_) => panic!("server kept a silent client for more than 10s"),
    }
    let waited = started.elapsed();
    assert!(
        (Duration::from_millis(900)..=Duration::from_secs(6)).contains(&waited),
        "silent client dropped after {waited:?}, expected about 1s"
    );
    drop(packets);

    // The slot is released and the abandoned session is still on record.
    let mut client = honeypot.client().await;
    let (_, rows) = client.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");

    honeypot.stop().await;
    let database = honeypot.open_database();
    let abandoned: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM connections WHERE username IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(
        abandoned, 1,
        "a connection that never authenticated must still be logged"
    );
    drop(database);
    honeypot.cleanup();
}

/// Small convenience so `expect_result` failures show a readable message.
trait ExpectRows {
    fn expect_ok_or_rows(self) -> usize;
}

impl ExpectRows for Response {
    fn expect_ok_or_rows(self) -> usize {
        match self {
            Response::ResultSet { rows, .. } => rows.len(),
            Response::Ok { affected_rows } => affected_rows as usize,
            other => panic!("expected a result set, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sql_semantics_over_the_wire() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    // COUNT(*) is one row, one column, aliased like MySQL reports it.
    let (columns, rows) = client
        .query("SELECT COUNT(*) AS total FROM users")
        .await
        .expect_result();
    assert_eq!(columns, vec!["total".to_string()]);
    assert_eq!(rows.len(), 1, "an aggregate must yield exactly one row");
    assert_eq!(rows[0][0], "3");

    // A filter that matches the named column returns exactly that row.
    let (_, rows) = client
        .query("SELECT username FROM users WHERE username = 'admin'")
        .await
        .expect_result();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], "admin");

    // A user that does not exist returns nothing at all.
    let (_, rows) = client
        .query("SELECT username FROM users WHERE username = 'no-such-user'")
        .await
        .expect_result();
    assert!(rows.is_empty(), "got {rows:?}");

    // `admin` appears in `email` too; the filter must still be column aware.
    let (_, rows) = client
        .query("SELECT username FROM users WHERE email = 'admin'")
        .await
        .expect_result();
    assert!(rows.is_empty(), "got {rows:?}");

    // COUNT after a filter counts the filtered set.
    let (_, rows) = client
        .query("SELECT COUNT(*) FROM users WHERE role = 'user'")
        .await
        .expect_result();
    assert_eq!(rows[0][0], "2");

    // The two LIMIT spellings must paginate identically.
    let (_, first) = client
        .query("SELECT id FROM users ORDER BY id ASC LIMIT 1, 2")
        .await
        .expect_result();
    let (_, second) = client
        .query("SELECT id FROM users ORDER BY id ASC LIMIT 2 OFFSET 1")
        .await
        .expect_result();
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0][0], "2");

    // ORDER BY ... DESC LIMIT
    let (_, rows) = client
        .query("SELECT id FROM users ORDER BY id DESC LIMIT 2")
        .await
        .expect_result();
    assert_eq!(rows[0][0], "3");

    // A condition the evaluator cannot model must not widen the result.
    let (_, rows) = client
        .query("SELECT * FROM users WHERE id LIKE '1%'")
        .await
        .expect_result();
    assert!(rows.len() <= 1, "got {rows:?}");

    // An unknown column is the MySQL error, not an empty answer.
    match client.query("SELECT * FROM users WHERE nope = 'x'").await {
        Response::Err { code, .. } => assert_eq!(code, 1054),
        other => panic!("expected ER_BAD_FIELD_ERROR, got {other:?}"),
    }

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn virtual_database_state_is_isolated_per_session() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut first = honeypot.client_with("mallory", None).await;
    let mut second = honeypot.client_with("victim", None).await;
    // `SHOW TABLES` needs a schema, exactly like a real server does.
    assert!(matches!(
        first.query("USE app_prod").await,
        Response::Ok { .. }
    ));
    assert!(matches!(
        second.query("USE app_prod").await,
        Response::Ok { .. }
    ));

    assert_eq!(
        first
            .query("INSERT INTO users (id, username, role) VALUES (9001, 'mallory', 'admin')")
            .await
            .expect_ok(),
        1
    );
    let (_, rows) = first
        .query("SELECT username FROM users WHERE id = 9001")
        .await
        .expect_result();
    assert_eq!(rows.len(), 1, "the writer must read its own insert back");
    assert_eq!(rows[0][0], "mallory");

    let (_, rows) = second
        .query("SELECT username FROM users WHERE id = 9001")
        .await
        .expect_result();
    assert!(rows.is_empty(), "another session must not see it: {rows:?}");

    // A drop in one session must not take the table away from the other.
    assert!(matches!(
        first.query("DROP TABLE users").await,
        Response::Ok { .. }
    ));
    match first.query("SELECT * FROM users").await {
        Response::Err { code, .. } => assert_eq!(code, 1146),
        other => panic!("expected ER_NO_SUCH_TABLE, got {other:?}"),
    }
    let (_, rows) = second.query("SELECT * FROM users").await.expect_result();
    assert_eq!(rows.len(), 3, "the other session keeps its own view");

    // CREATE TABLE is visible in SHOW TABLES and in information_schema.
    assert!(matches!(
        first
            .query(
                "CREATE TABLE loot (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, note varchar(32))"
            )
            .await,
        Response::Ok { .. }
    ));
    let (_, rows) = first.query("SHOW TABLES").await.expect_result();
    let names: Vec<String> = rows.into_iter().map(|row| row[0].clone()).collect();
    assert!(names.contains(&"loot".to_string()), "got {names:?}");
    let (_, rows) = second.query("SHOW TABLES").await.expect_result();
    let names: Vec<String> = rows.into_iter().map(|row| row[0].clone()).collect();
    assert!(!names.contains(&"loot".to_string()), "got {names:?}");

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_statements_answer_with_the_binary_protocol() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (columns, rows) = client
        .binary_query("SELECT COUNT(*) FROM users")
        .await
        .expect_result();
    assert_eq!(columns, vec!["COUNT(*)".to_string()]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], "3");

    let (columns, rows) = client
        .binary_query("SELECT username FROM users WHERE username = 'admin'")
        .await
        .expect_result();
    assert_eq!(columns, vec!["username".to_string()]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], "admin");

    // An unknown statement handle is the documented error, and the session
    // survives it.
    match client.send_command(0x17, &[0xff, 0xff, 0xff, 0xff]).await {
        Response::Err { code, .. } => assert_eq!(code, 1243),
        other => panic!("expected ER_UNKNOWN_STMT_HANDLER, got {other:?}"),
    }
    let (_, rows) = client.query("SELECT 1").await.expect_result();
    assert_eq!(rows[0][0], "1");

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn change_user_switches_identity_and_is_audited() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client_with("root", None).await;

    let mut body = Vec::new();
    body.extend_from_slice(b"alice\0");
    body.push(0); // empty auth response
    body.extend_from_slice(b"mysql\0");
    body.extend_from_slice(&45u16.to_le_bytes());
    body.extend_from_slice(b"caching_sha2_password\0");
    assert!(matches!(
        client.send_command(0x11, &body).await,
        Response::Ok { .. }
    ));

    let (_, rows) = client.query("SELECT CURRENT_USER()").await.expect_result();
    assert_eq!(rows[0][0], "alice@%");
    let (_, rows) = client.query("SELECT DATABASE()").await.expect_result();
    assert_eq!(rows[0][0], "mysql");

    honeypot.stop().await;
    let database = honeypot.open_database();
    let username: String = database
        .query_row(
            "SELECT username FROM connections ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("connection row");
    assert_eq!(
        username, "alice",
        "the connection row must name the identity in use"
    );
    let switches: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM queries WHERE query_type = 'CHANGE_USER'",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(switches, 1, "the switch itself must be audited");
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_counters_account_for_every_event() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;
    for sql in ["SELECT 1", "SHOW DATABASES", "SELECT COUNT(*) FROM users"] {
        client.query(sql).await;
    }
    honeypot.stop().await;

    let stats = honeypot.logger.stats();
    assert_eq!(
        stats.offered(),
        stats.enqueued + stats.dropped,
        "record() calls must be fully accounted: {stats:?}"
    );
    assert_eq!(
        stats.enqueued,
        stats.written + stats.failed,
        "every queued event is committed or counted as failed: {stats:?}"
    );
    assert_eq!(stats.pending(), 0, "nothing may stay in flight: {stats:?}");
    assert_eq!(stats.dropped, 0, "{stats:?}");
    assert_eq!(stats.failed, 0, "{stats:?}");
    // connect + identified + authenticated + 3 queries + disconnect
    assert_eq!(stats.written, 7, "{stats:?}");

    let database = honeypot.open_database();
    let queries: i64 = database
        .query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))
        .expect("count");
    assert_eq!(queries, 3);
    let connections: i64 = database
        .query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0))
        .expect("count");
    assert_eq!(connections, 1);
    drop(database);
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_statements_bind_typed_parameters() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (statement, parameters) = client
        .prepare("SELECT username FROM app_prod.users WHERE id = ?")
        .await;
    assert_eq!(parameters, 1, "one placeholder, one parameter");

    // An integer parameter against a numeric column.
    let (columns, rows) = client
        .execute(statement, &[Param::Int(1)], true)
        .await
        .expect_result();
    assert_eq!(columns, vec!["username".to_string()]);
    assert_eq!(rows, vec![vec!["admin".to_string()]]);

    // The same prepared statement re-executed with another value.
    let (_, rows) = client
        .execute(statement, &[Param::Int(3)], true)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["bob".to_string()]]);

    // `new_params_bound_flag = 0`: the client reuses the previous types.
    let (_, rows) = client
        .execute(statement, &[Param::Int(2)], false)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["alice".to_string()]]);

    // A value matching nothing is an empty result set, not an error.
    let (_, rows) = client
        .execute(statement, &[Param::Int(99)], true)
        .await
        .expect_result();
    assert!(rows.is_empty());

    client.close_statement(statement).await;
    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_statements_bind_strings_floats_and_null() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (statement, _) = client
        .prepare("SELECT username FROM app_prod.users WHERE username = ?")
        .await;
    let (_, rows) = client
        .execute(statement, &[Param::Str("alice".to_string())], true)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["alice".to_string()]]);

    // The case-insensitive collation applies to a bound string too.
    let (_, rows) = client
        .execute(statement, &[Param::Str("ALICE".to_string())], true)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["alice".to_string()]]);

    // A NULL parameter matches nothing, like `= NULL` in SQL.
    let (_, rows) = client
        .execute(statement, &[Param::Null], true)
        .await
        .expect_result();
    assert!(rows.is_empty(), "a NULL parameter must not match");
    client.close_statement(statement).await;

    // A double parameter against a numeric column.
    let (statement, _) = client
        .prepare("SELECT username FROM app_prod.users WHERE id > ?")
        .await;
    let (_, rows) = client
        .execute(statement, &[Param::Double(2.5)], true)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["bob".to_string()]]);
    client.close_statement(statement).await;

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_string_cannot_change_the_statement_shape() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (statement, _) = client
        .prepare("SELECT username FROM app_prod.users WHERE username = ?")
        .await;
    // The classic injection payload: bound as data it is just a string that
    // matches no row, instead of widening the predicate.
    for payload in [
        "' OR 1=1 -- ",
        "admin' --",
        "%",
        "admin' OR username LIKE '%",
    ] {
        let (_, rows) = client
            .execute(statement, &[Param::Str(payload.to_string())], true)
            .await
            .expect_result();
        assert!(
            rows.is_empty(),
            "payload {payload:?} widened the predicate to {} rows",
            rows.len()
        );
    }
    client.close_statement(statement).await;
    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_statements_reject_malformed_executions() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (statement, parameters) = client
        .prepare("SELECT username FROM app_prod.users WHERE id = ?")
        .await;
    assert_eq!(parameters, 1);

    // An unknown statement id.
    match client.execute(999, &[Param::Int(1)], true).await {
        Response::Err { code, .. } => assert_eq!(code, 1243),
        other => panic!("unknown statement must be refused, got {other:?}"),
    }

    // A truncated payload: the type block promises a value that is not there.
    let mut truncated = execute_payload(statement, &[Param::Int(1)], true, 0x00, 1);
    truncated.truncate(truncated.len() - 4);
    match client.execute_raw(&truncated).await {
        Response::Err { code, .. } => assert_eq!(code, 1210),
        other => panic!("a truncated payload must be refused, got {other:?}"),
    }

    // No type block and no previous execute to reuse.
    let mut no_types = execute_payload(statement, &[Param::Int(1)], false, 0x00, 1);
    no_types.truncate(no_types.len() - 8);
    match client.execute_raw(&no_types).await {
        Response::Err { code, .. } => assert_eq!(code, 1210),
        other => panic!("a type block is required on the first execute, got {other:?}"),
    }

    // An iteration count other than 1.
    match client
        .execute_raw(&execute_payload(statement, &[Param::Int(1)], true, 0x00, 2))
        .await
    {
        Response::Err { code, .. } => assert_eq!(code, 1210),
        other => panic!("a bad iteration count must be refused, got {other:?}"),
    }

    // A cursor request is refused rather than half-opened.
    match client
        .execute_raw(&execute_payload(statement, &[Param::Int(1)], true, 0x01, 1))
        .await
    {
        Response::Err { code, .. } => assert_eq!(code, 1295),
        other => panic!("a cursor request must be refused, got {other:?}"),
    }

    // The session is still usable afterwards.
    let (_, rows) = client
        .execute(statement, &[Param::Int(1)], true)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["admin".to_string()]]);
    client.close_statement(statement).await;

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stmt_reset_and_close_clear_statement_state() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (statement, _) = client
        .prepare("SELECT username FROM app_prod.users WHERE id = ?")
        .await;
    let (_, rows) = client
        .execute(statement, &[Param::Int(1)], true)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["admin".to_string()]]);

    // `COM_STMT_RESET` discards the cached parameter types, so a execute that
    // reuses them must now be refused instead of binding stale types.
    client.reset_statement(statement).await;
    let mut reuse = execute_payload(statement, &[Param::Int(2)], false, 0x00, 1);
    reuse.truncate(reuse.len() - 8);
    match client.execute_raw(&reuse).await {
        Response::Err { code, .. } => assert_eq!(code, 1210),
        other => panic!("reset must clear the type cache, got {other:?}"),
    }
    // Sending the types again works.
    let (_, rows) = client
        .execute(statement, &[Param::Int(2)], true)
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["alice".to_string()]]);

    // After `COM_STMT_CLOSE` the id is unknown.
    client.close_statement(statement).await;
    match client.execute(statement, &[Param::Int(1)], true).await {
        Response::Err { code, .. } => assert_eq!(code, 1243),
        other => panic!("a closed statement must be unknown, got {other:?}"),
    }

    honeypot.stop().await;
    honeypot.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_dml_reports_affected_rows_and_audits_the_bound_values() {
    let mut honeypot = TestHoneypot::start(base_config()).await;
    let mut client = honeypot.client().await;

    let (statement, parameters) = client
        .prepare("UPDATE app_prod.users SET role = ? WHERE id = ?")
        .await;
    assert_eq!(parameters, 2);
    let affected = client
        .execute(
            statement,
            &[Param::Str("auditor".to_string()), Param::Int(2)],
            true,
        )
        .await
        .expect_ok();
    assert_eq!(affected, 1);
    client.close_statement(statement).await;

    // The change is visible to the session that made it.
    let (_, rows) = client
        .query("SELECT role FROM app_prod.users WHERE id = 2")
        .await
        .expect_result();
    assert_eq!(rows, vec![vec!["auditor".to_string()]]);
    honeypot.stop().await;

    // The audit row carries the statement with the bound values rendered in, so
    // the record matches what actually executed.
    let database = honeypot.open_database();
    let recorded: String = database
        .query_row(
            "SELECT sql_text FROM queries WHERE sql_text LIKE '%app_prod.users%' \
             AND query_type = 'UPDATE' ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("audit row");
    assert!(
        recorded.contains("'auditor'"),
        "the bound value must appear in the audit row: {recorded}"
    );
    assert!(
        recorded.contains('2'),
        "the bound key must appear in the audit row: {recorded}"
    );
    drop(database);
    honeypot.cleanup();
}
