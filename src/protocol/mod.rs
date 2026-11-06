// SPDX-License-Identifier: GPL-3.0-only
//! MySQL wire protocol primitives.
//!
//! Only the subset a honeypot needs is implemented: packet framing, the
//! version 10 initial handshake, the 4.1 handshake response, OK/ERR/EOF
//! packets, text protocol result sets and the binary parameter block of
//! `COM_STMT_EXECUTE`.

pub mod execute;
pub mod handshake;
pub mod packet;
pub mod response;

use std::fmt;

/// `CLIENT_LONG_PASSWORD`
pub const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
/// `CLIENT_LONG_FLAG`
pub const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
/// `CLIENT_CONNECT_WITH_DB`
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
/// `CLIENT_PROTOCOL_41`
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
/// `CLIENT_SSL`
pub const CLIENT_SSL: u32 = 0x0000_0800;
/// `CLIENT_LOCAL_FILES` — never advertised, the honeypot reads nothing for a client.
pub const CLIENT_LOCAL_FILES: u32 = 0x0000_0080;
/// `CLIENT_TRANSACTIONS`
pub const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
/// `CLIENT_SECURE_CONNECTION`
pub const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
/// `CLIENT_MULTI_RESULTS`
pub const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
/// `CLIENT_PLUGIN_AUTH`
pub const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
/// `CLIENT_CONNECT_ATTRS`
pub const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
/// `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA`
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
/// `CLIENT_DEPRECATE_EOF`
pub const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;

/// Capability flags advertised in the initial handshake.
///
/// `CLIENT_SSL`, `CLIENT_COMPRESS`, `CLIENT_LOCAL_FILES` and
/// `CLIENT_MULTI_STATEMENTS` are deliberately absent: the honeypot speaks no
/// TLS, no compression, never reads files for a client and answers exactly one
/// statement per `COM_QUERY`.
pub const SERVER_CAPABILITIES: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_CONNECT_ATTRS
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | CLIENT_DEPRECATE_EOF;

/// `SERVER_STATUS_AUTOCOMMIT`
pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;

/// `utf8mb4_general_ci`
pub const CHARSET_UTF8MB4: u8 = 45;

/// Protocol version 10 — the only one this honeypot implements.
pub const PROTOCOL_VERSION: u8 = 10;

// ---------------------------------------------------------------------------
// Client commands
// ---------------------------------------------------------------------------
pub const COM_QUIT: u8 = 0x01;
pub const COM_INIT_DB: u8 = 0x02;
pub const COM_QUERY: u8 = 0x03;
pub const COM_FIELD_LIST: u8 = 0x04;
pub const COM_STATISTICS: u8 = 0x09;
pub const COM_PROCESS_INFO: u8 = 0x0a;
pub const COM_DEBUG: u8 = 0x0d;
pub const COM_PING: u8 = 0x0e;
pub const COM_CHANGE_USER: u8 = 0x11;
pub const COM_STMT_PREPARE: u8 = 0x16;
pub const COM_STMT_EXECUTE: u8 = 0x17;
pub const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
pub const COM_STMT_CLOSE: u8 = 0x19;
pub const COM_STMT_RESET: u8 = 0x1a;
pub const COM_STMT_FETCH: u8 = 0x1c;
pub const COM_SET_OPTION: u8 = 0x1b;
pub const COM_RESET_CONNECTION: u8 = 0x1f;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------
pub const ER_CON_COUNT_ERROR: u16 = 1040;
pub const ER_HANDSHAKE_ERROR: u16 = 1043;
pub const ER_ACCESS_DENIED_ERROR: u16 = 1045;
pub const ER_NO_DB_ERROR: u16 = 1046;
pub const ER_UNKNOWN_COM_ERROR: u16 = 1047;
pub const ER_BAD_DB_ERROR: u16 = 1049;
pub const ER_PARSE_ERROR: u16 = 1064;
pub const ER_EMPTY_QUERY: u16 = 1065;
pub const ER_NO_SUCH_TABLE: u16 = 1146;
pub const ER_NOT_ALLOWED_COMMAND: u16 = 1148;
pub const ER_UNSUPPORTED_PS: u16 = 1295;

/// Protocol level failures. Every one of them terminates a single session —
/// nothing here is fatal for the process.
#[derive(Debug)]
pub enum Error {
    /// Underlying socket error.
    Io(std::io::Error),
    /// Peer closed the connection at a packet boundary.
    Eof,
    /// A packet claimed (or the accumulated stream exceeded) the configured cap.
    PacketTooLarge { len: usize, max: usize },
    /// Structurally invalid payload for the expected packet type.
    Malformed(&'static str),
    /// Well formed but not implemented by this honeypot.
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Eof => f.write_str("peer closed the connection"),
            Self::PacketTooLarge { len, max } => {
                write!(f, "packet of {len} bytes exceeds limit of {max} bytes")
            }
            Self::Malformed(what) => write!(f, "malformed packet: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        if value.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::Eof
        } else {
            Self::Io(value)
        }
    }
}

/// Convenience alias for protocol results.
pub type Result<T> = std::result::Result<T, Error>;
