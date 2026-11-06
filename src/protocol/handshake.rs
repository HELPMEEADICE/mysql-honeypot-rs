// SPDX-License-Identifier: GPL-3.0-only
//! Initial handshake (protocol version 10) and the 4.1 handshake response.

use super::packet::{PayloadBuilder, PayloadReader};
use super::{
    CLIENT_CONNECT_ATTRS, CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH,
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION,
    CLIENT_SSL, CLIENT_TRANSACTIONS, Error, PROTOCOL_VERSION, Result,
};

/// Bytes of scramble/nonce the server sends in the initial handshake.
pub const SALT_LEN: usize = 20;

/// Parsed `HandshakeResponse41` payload.
#[derive(Debug, Clone, Default)]
pub struct HandshakeResponse {
    /// Capability flags the client negotiated.
    pub capabilities: u32,
    /// Largest packet the client is willing to receive.
    pub max_packet_size: u32,
    /// Client character set.
    pub charset: u8,
    /// Login name exactly as the client sent it.
    pub username: String,
    /// Scrambled authentication response (never a usable secret).
    pub auth_response: Vec<u8>,
    /// Schema requested through `CLIENT_CONNECT_WITH_DB`.
    pub database: Option<String>,
    /// Authentication plugin the client answered for.
    pub auth_plugin: Option<String>,
    /// `CLIENT_CONNECT_ATTRS` key/value pairs.
    pub attrs: Vec<(String, String)>,
}

impl HandshakeResponse {
    /// Compact, log friendly rendering of the client's connect attributes.
    ///
    /// Typical clients send `_client_name=libmysql`, `_client_version=8.0.36`,
    /// `_os=Linux`, `_pid=1234`, `program_name=mysql`.
    pub fn client_summary(&self) -> String {
        if self.attrs.is_empty() {
            return String::new();
        }
        let mut parts: Vec<String> = self
            .attrs
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        parts.sort();
        parts.join(",")
    }
}

/// Build the server's `HandshakeV10` payload.
///
/// `salt` must be at least [`SALT_LEN`] bytes and must not contain interior
/// NULs (the auth-plugin-data block is NUL terminated).
pub fn build_initial_handshake(
    connection_id: u32,
    server_version: &str,
    salt: &[u8],
    capabilities: u32,
    charset: u8,
    status: u16,
    auth_plugin: &str,
) -> Result<Vec<u8>> {
    if salt.len() < SALT_LEN {
        return Err(Error::Malformed("salt shorter than 20 bytes"));
    }
    let mut builder = PayloadBuilder::with_capacity(96);
    builder
        .u8(PROTOCOL_VERSION)
        .nul_str(server_version)
        .u32le(connection_id)
        .bytes(&salt[..8])
        .u8(0) // filler
        .u16le((capabilities & 0xffff) as u16)
        .u8(charset)
        .u16le(status)
        .u16le(((capabilities >> 16) & 0xffff) as u16)
        .u8((SALT_LEN + 1) as u8) // auth-plugin-data length
        .zeros(10) // reserved
        .bytes(&salt[8..SALT_LEN])
        .u8(0) // auth-plugin-data terminator
        .nul_str(auth_plugin);
    Ok(builder.into_vec())
}

/// Whether a payload is an `SSLRequest` rather than a full handshake response.
///
/// The honeypot advertises no `CLIENT_SSL`, so this only triggers for clients
/// that insist on TLS regardless of the advertised flags.
pub fn is_ssl_request(payload: &[u8]) -> bool {
    payload.len() >= 4
        && u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) & CLIENT_SSL != 0
}

/// Parse a `HandshakeResponse41` payload.
///
/// Unknown trailing bytes are ignored; every short read is an error instead of
/// a panic.
pub fn parse_handshake_response(payload: &[u8]) -> Result<HandshakeResponse> {
    let mut reader = PayloadReader::new(payload);
    if payload.len() < 32 {
        return Err(Error::Malformed("handshake response shorter than 32 bytes"));
    }
    let capabilities = reader.u32le()?;
    if capabilities & CLIENT_PROTOCOL_41 == 0 {
        // Pre-4.1 clients are out of scope; they are answered with an ERR packet.
        return Err(Error::Unsupported("pre-4.1 handshake response"));
    }
    let max_packet_size = reader.u32le()?;
    let charset = reader.u8()?;
    reader.skip(23)?;
    let username = reader.nul_str()?;

    let auth_response = if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        reader
            .lenenc_bytes()?
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    } else if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let len = reader.u8()? as usize;
        reader.take(len)?.to_vec()
    } else {
        let mut bytes = Vec::new();
        loop {
            match reader.u8() {
                Ok(0) | Err(_) => break,
                Ok(byte) => bytes.push(byte),
            }
        }
        bytes
    };

    let mut database = None;
    if capabilities & CLIENT_CONNECT_WITH_DB != 0 && !reader.is_empty() {
        let name = reader.nul_str()?;
        if !name.is_empty() {
            database = Some(name);
        }
    }

    let mut auth_plugin = None;
    if capabilities & CLIENT_PLUGIN_AUTH != 0 && !reader.is_empty() {
        let name = reader.nul_str()?;
        if !name.is_empty() {
            auth_plugin = Some(name);
        }
    }

    let mut attrs = Vec::new();
    if capabilities & CLIENT_CONNECT_ATTRS != 0
        && !reader.is_empty()
        && let Ok(Some(declared)) = reader.lenenc_int()
    {
        let start = reader.position();
        let budget = (declared as usize).min(reader.remaining());
        // Cap the number of pairs kept: a hostile client must not be able to
        // grow the log entry on our side without bound.
        while reader.position() - start < budget && attrs.len() < 32 {
            let Ok(Some(key)) = reader.lenenc_str() else {
                break;
            };
            let Ok(Some(value)) = reader.lenenc_str() else {
                break;
            };
            if key.is_empty() && value.is_empty() {
                break;
            }
            attrs.push((key, value));
        }
    }

    Ok(HandshakeResponse {
        capabilities,
        max_packet_size,
        charset,
        username,
        auth_response,
        database,
        auth_plugin,
        attrs,
    })
}

/// Build an `AuthSwitchRequest` asking the client for another plugin.
pub fn build_auth_switch_request(plugin: &str, salt: &[u8]) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(32);
    builder.u8(0xfe).nul_str(plugin);
    let take = salt.len().min(SALT_LEN);
    builder.bytes(&salt[..take]);
    if take == SALT_LEN {
        builder.u8(0);
    }
    builder.into_vec()
}

/// Whether the client's flags indicate it expects an EOF packet after the
/// column definitions (only true when it did not negotiate `DEPRECATE_EOF`).
pub fn wants_eof_terminators(capabilities: u32) -> bool {
    capabilities & super::CLIENT_DEPRECATE_EOF == 0
}

/// Whether the negotiated flags include transaction status fields.
pub fn has_transactions(capabilities: u32) -> bool {
    capabilities & CLIENT_TRANSACTIONS != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SERVER_CAPABILITIES;

    fn sample_salt() -> Vec<u8> {
        (0u8..20).map(|i| b'a' + i).collect()
    }

    #[test]
    fn initial_handshake_layout() {
        let salt = sample_salt();
        let payload = build_initial_handshake(
            7,
            "8.0.36",
            &salt,
            SERVER_CAPABILITIES,
            super::super::CHARSET_UTF8MB4,
            2,
            "caching_sha2_password",
        )
        .expect("build");

        let mut reader = PayloadReader::new(&payload);
        assert_eq!(reader.u8().expect("protocol"), PROTOCOL_VERSION);
        assert_eq!(reader.nul_str().expect("version"), "8.0.36");
        assert_eq!(reader.u32le().expect("thread id"), 7);
        assert_eq!(reader.take(8).expect("salt part 1"), &salt[..8]);
        assert_eq!(reader.u8().expect("filler"), 0);
        let cap_low = reader.u16le().expect("caps low") as u32;
        assert_eq!(reader.u8().expect("charset"), super::super::CHARSET_UTF8MB4);
        assert_eq!(reader.u16le().expect("status"), 2);
        let cap_high = reader.u16le().expect("caps high") as u32;
        assert_eq!(
            cap_low | (cap_high << 16),
            SERVER_CAPABILITIES,
            "capabilities must survive the split"
        );
        assert_eq!(reader.u8().expect("auth data len"), 21);
        reader.skip(10).expect("reserved");
        assert_eq!(reader.take(12).expect("salt part 2"), &salt[8..20]);
        assert_eq!(reader.u8().expect("salt terminator"), 0);
        assert_eq!(reader.nul_str().expect("plugin"), "caching_sha2_password");
        assert!(reader.is_empty());
        const {
            assert!(
                SERVER_CAPABILITIES & CLIENT_SSL == 0,
                "TLS must not be advertised"
            )
        };
        const {
            assert!(
                SERVER_CAPABILITIES & super::super::CLIENT_LOCAL_FILES == 0,
                "LOAD DATA LOCAL must not be advertised"
            )
        };
    }

    fn build_response(
        capabilities: u32,
        username: &str,
        auth: &[u8],
        db: Option<&str>,
        plugin: Option<&str>,
    ) -> Vec<u8> {
        let mut builder = PayloadBuilder::new();
        builder
            .u32le(capabilities)
            .u32le(16 * 1024 * 1024)
            .u8(45)
            .zeros(23)
            .nul_str(username);
        if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            builder.lenenc_int(auth.len() as u64).bytes(auth);
        } else if capabilities & CLIENT_SECURE_CONNECTION != 0 {
            builder.u8(auth.len() as u8).bytes(auth);
        }
        if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
            builder.nul_str(db.unwrap_or(""));
        }
        if capabilities & CLIENT_PLUGIN_AUTH != 0 {
            builder.nul_str(plugin.unwrap_or(""));
        }
        builder.into_vec()
    }

    #[test]
    fn parses_lenenc_secure_connection_and_attrs() {
        let caps = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            | CLIENT_CONNECT_WITH_DB
            | CLIENT_CONNECT_ATTRS;
        let auth = vec![0xAAu8; 32];
        let mut payload = build_response(
            caps,
            "root",
            &auth,
            Some("app_prod"),
            Some("caching_sha2_password"),
        );
        // attributes block
        let mut attrs = PayloadBuilder::new();
        attrs
            .lenenc_str("_client_name")
            .lenenc_str("libmysql")
            .lenenc_str("_client_version")
            .lenenc_str("8.0.36")
            .lenenc_str("_os")
            .lenenc_str("Linux");
        let attrs = attrs.into_vec();
        let mut tail = PayloadBuilder::new();
        tail.lenenc_int(attrs.len() as u64).bytes(&attrs);
        payload.extend_from_slice(&tail.into_vec());

        let parsed = parse_handshake_response(&payload).expect("parse");
        assert_eq!(parsed.username, "root");
        assert_eq!(parsed.database.as_deref(), Some("app_prod"));
        assert_eq!(parsed.auth_plugin.as_deref(), Some("caching_sha2_password"));
        assert_eq!(parsed.auth_response, auth);
        assert_eq!(parsed.attrs.len(), 3);
        assert_eq!(
            parsed.client_summary(),
            "_client_name=libmysql,_client_version=8.0.36,_os=Linux"
        );
    }

    #[test]
    fn parses_secure_connection_without_lenenc() {
        let caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        let payload = build_response(
            caps,
            "admin",
            &[0x11u8; 20],
            None,
            Some("mysql_native_password"),
        );
        let parsed = parse_handshake_response(&payload).expect("parse");
        assert_eq!(parsed.username, "admin");
        assert_eq!(parsed.auth_response.len(), 20);
        assert_eq!(parsed.auth_plugin.as_deref(), Some("mysql_native_password"));
        assert!(parsed.database.is_none());
    }

    #[test]
    fn rejects_short_and_pre41_payloads() {
        assert!(parse_handshake_response(b"\x01\x02").is_err());
        let mut short = build_response(
            CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION,
            "u",
            &[],
            None,
            None,
        );
        short.truncate(20);
        assert!(parse_handshake_response(&short).is_err());
        // Valid length but PROTOCOL_41 cleared.
        let mut legacy = build_response(
            CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION,
            "u",
            &[],
            None,
            None,
        );
        legacy[0] = 0;
        legacy[1] = 0;
        match parse_handshake_response(&legacy) {
            Err(Error::Unsupported(_)) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn ssl_request_is_detected() {
        let caps = CLIENT_PROTOCOL_41 | CLIENT_SSL;
        let payload = build_response(caps, "", &[], None, None);
        assert!(is_ssl_request(&payload));
        assert!(!is_ssl_request(b"\x00"));
    }

    #[test]
    fn salt_too_short_is_rejected() {
        assert!(
            build_initial_handshake(1, "8.0.36", b"short", SERVER_CAPABILITIES, 45, 2, "x")
                .is_err()
        );
    }

    #[test]
    fn eof_terminator_negotiation() {
        assert!(wants_eof_terminators(CLIENT_PROTOCOL_41));
        assert!(!wants_eof_terminators(
            CLIENT_PROTOCOL_41 | super::super::CLIENT_DEPRECATE_EOF
        ));
        assert!(has_transactions(CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS));
    }
}
