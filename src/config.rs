// SPDX-License-Identifier: GPL-3.0-only
//! `config.toml` handling.
//!
//! Every field has a sane default, so a missing or partial file still yields a
//! runnable configuration; out-of-range values are clamped instead of rejected.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Defaults for the `[server]` table.
pub const DEFAULT_PORT: u16 = 3306;
/// Default advertised server version.
pub const DEFAULT_VERSION: &str = "8.0.36";

/// Root configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub authentication: AuthConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
}

/// `[server]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind. Only this listener is ever opened.
    pub host: String,
    /// TCP port to bind.
    pub port: u16,
    /// Version string reported in the handshake and in `VERSION()`.
    pub version: String,
    /// Upper bound on simultaneous sessions.
    pub max_connections: usize,
    /// Idle timeout once logged in.
    pub idle_timeout_seconds: u64,
    /// Deadline for a client to complete the handshake.
    pub handshake_timeout_seconds: u64,
    /// Largest logical MySQL payload accepted from a client.
    pub max_packet_size: usize,
    /// Bytes of SQL stored per statement.
    pub max_sql_length: usize,
    /// Grace period for in-flight sessions on shutdown.
    pub shutdown_grace_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: DEFAULT_PORT,
            version: DEFAULT_VERSION.to_string(),
            max_connections: 256,
            idle_timeout_seconds: 300,
            handshake_timeout_seconds: 10,
            max_packet_size: 1_048_576,
            max_sql_length: 16_384,
            shutdown_grace_seconds: 5,
        }
    }
}

/// `[authentication]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Accept every credential pair. Kept as a switch for comparative research;
    /// `true` is the honeypot's whole point.
    pub always_accept: bool,
    /// Lower bound of the random login delay, in milliseconds.
    pub delay_min_ms: u64,
    /// Upper bound of the random login delay, in milliseconds.
    pub delay_max_ms: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            always_accept: true,
            delay_min_ms: 2_000,
            delay_max_ms: 6_000,
        }
    }
}

/// `[database]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// SQLite file receiving every event.
    pub sqlite_path: String,
    /// Enable WAL journaling.
    pub enable_wal: bool,
    /// Capacity of the bounded log queue; overflow is dropped, never blocked.
    pub queue_capacity: usize,
    /// SQLite busy timeout in milliseconds.
    pub busy_timeout_ms: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            sqlite_path: "./honeypot.db".to_string(),
            enable_wal: true,
            queue_capacity: 4_096,
            busy_timeout_ms: 5_000,
        }
    }
}

/// `[logging]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `tracing` filter directive.
    pub level: String,
    /// Emit one log line per received statement.
    pub log_queries: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            log_queries: true,
        }
    }
}

/// Configuration loading failure.
#[derive(Debug)]
pub enum ConfigError {
    /// The file exists but could not be read.
    Io(PathBuf, std::io::Error),
    /// The file is not valid TOML or does not match the schema.
    Parse(PathBuf, toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "cannot read {}: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "invalid config {}: {err}", path.display()),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Load `path`, falling back to defaults when the file does not exist.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            let mut config = Self::default();
            config.sanitize();
            return Ok(config);
        }
        let text = std::fs::read_to_string(path)
            .map_err(|err| ConfigError::Io(path.to_path_buf(), err))?;
        let mut config: Self =
            toml::from_str(&text).map_err(|err| ConfigError::Parse(path.to_path_buf(), err))?;
        config.sanitize();
        Ok(config)
    }

    /// Parse from an in-memory TOML document (used by tests).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let mut config: Self = toml::from_str(text)
            .map_err(|err| ConfigError::Parse(PathBuf::from("<memory>"), err))?;
        config.sanitize();
        Ok(config)
    }

    /// Clamp every value into a range the honeypot can actually run with.
    pub fn sanitize(&mut self) {
        if self.server.host.trim().is_empty() {
            self.server.host = ServerConfig::default().host;
        }
        // Accept both `::1` and `[::1]`: the brackets are only URI syntax, the
        // resolver wants the bare address.
        let host = self.server.host.trim().to_string();
        self.server.host = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(&host)
            .to_string();
        if self.server.version.trim().is_empty() {
            self.server.version = DEFAULT_VERSION.to_string();
        }
        self.server.max_connections = self.server.max_connections.clamp(1, 65_535);
        self.server.idle_timeout_seconds = self.server.idle_timeout_seconds.clamp(5, 86_400);
        self.server.handshake_timeout_seconds = self.server.handshake_timeout_seconds.clamp(1, 300);
        self.server.max_packet_size = self.server.max_packet_size.clamp(4_096, 64 * 1024 * 1024);
        self.server.max_sql_length = self.server.max_sql_length.clamp(64, 1024 * 1024);
        self.server.shutdown_grace_seconds = self.server.shutdown_grace_seconds.clamp(0, 120);

        if self.authentication.delay_max_ms < self.authentication.delay_min_ms {
            std::mem::swap(
                &mut self.authentication.delay_min_ms,
                &mut self.authentication.delay_max_ms,
            );
        }
        // A zero-length delay would defeat the trap; keep at least a millisecond.
        self.authentication.delay_min_ms = self.authentication.delay_min_ms.max(1);

        if self.database.sqlite_path.trim().is_empty() {
            self.database.sqlite_path = DatabaseConfig::default().sqlite_path;
        }
        self.database.queue_capacity = self.database.queue_capacity.clamp(16, 1_048_576);
        self.database.busy_timeout_ms = self.database.busy_timeout_ms.clamp(50, 60_000);

        if self.logging.level.trim().is_empty() {
            self.logging.level = LoggingConfig::default().level;
        }
    }

    /// Path of the SQLite log database.
    pub fn sqlite_path(&self) -> &str {
        &self.database.sqlite_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_shipped_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 3306);
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.version, "8.0.36");
        assert_eq!(config.server.max_connections, 256);
        assert_eq!(config.server.idle_timeout_seconds, 300);
        assert!(config.authentication.always_accept);
        assert_eq!(config.authentication.delay_min_ms, 2_000);
        assert_eq!(config.authentication.delay_max_ms, 6_000);
        assert_eq!(config.database.sqlite_path, "./honeypot.db");
        assert!(config.database.enable_wal);
        assert_eq!(config.logging.level, "info");
        assert!(config.logging.log_queries);
    }

    #[test]
    fn parses_the_documented_sample() {
        let text = r#"
[server]
host = "127.0.0.1"
port = 13306
version = "8.0.36"
max_connections = 64
idle_timeout_seconds = 120

[authentication]
always_accept = true
delay_min_ms = 1500
delay_max_ms = 2500

[database]
sqlite_path = "/var/lib/mysql-honeypot/honeypot.db"
enable_wal = true

[logging]
level = "debug"
log_queries = false
"#;
        let config = Config::from_toml(text).expect("parse");
        assert_eq!(config.server.port, 13_306);
        assert_eq!(config.server.max_connections, 64);
        assert_eq!(config.authentication.delay_min_ms, 1_500);
        assert_eq!(config.logging.level, "debug");
        assert!(!config.logging.log_queries);
        assert_eq!(config.sqlite_path(), "/var/lib/mysql-honeypot/honeypot.db");
    }

    #[test]
    fn partial_documents_inherit_defaults() {
        let config = Config::from_toml("[server]\nport = 4000\n").expect("parse");
        assert_eq!(config.server.port, 4000);
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.authentication.delay_max_ms, 6_000);
        assert!(config.database.enable_wal);
    }

    #[test]
    fn inverted_delay_bounds_are_swapped() {
        let config =
            Config::from_toml("[authentication]\ndelay_min_ms = 9000\ndelay_max_ms = 1000\n")
                .expect("parse");
        assert_eq!(config.authentication.delay_min_ms, 1_000);
        assert_eq!(config.authentication.delay_max_ms, 9_000);
    }

    #[test]
    fn absurd_values_are_clamped() {
        let config = Config::from_toml(
            "[server]\nmax_connections = 0\nmax_packet_size = 1\nidle_timeout_seconds = 0\n\n[database]\nqueue_capacity = 0\n",
        )
        .expect("parse");
        assert_eq!(config.server.max_connections, 1);
        assert_eq!(config.server.max_packet_size, 4_096);
        assert_eq!(config.server.idle_timeout_seconds, 5);
        assert_eq!(config.database.queue_capacity, 16);
    }

    #[test]
    fn ipv6_hosts_are_normalised() {
        // Brackets are URI syntax, the resolver wants the bare address.
        let config = Config::from_toml("[server]\nhost = \"[::1]\"\n").expect("parse");
        assert_eq!(config.server.host, "::1");
        let config = Config::from_toml("[server]\nhost = \"::\"\n").expect("parse");
        assert_eq!(config.server.host, "::");
        let config = Config::from_toml("[server]\nhost = \" [::] \"\n").expect("parse");
        assert_eq!(config.server.host, "::");
    }

    #[test]
    fn missing_file_yields_defaults() {
        let config = Config::load(Path::new("definitely-not-here.toml")).expect("defaults");
        assert_eq!(config.server.port, DEFAULT_PORT);
    }

    #[test]
    fn malformed_document_is_reported() {
        let err = Config::from_toml("[server]\nport = \"not a number\"\n").expect_err("must fail");
        assert!(matches!(err, ConfigError::Parse(_, _)));
        assert!(err.to_string().contains("invalid config"));
    }
}
