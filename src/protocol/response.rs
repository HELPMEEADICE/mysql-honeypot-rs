// SPDX-License-Identifier: GPL-3.0-only
//! Encoders for server responses: OK, ERR, EOF, column definitions, rows and
//! whole text-protocol result sets.

use tokio::io::{AsyncRead, AsyncWrite};

use super::packet::{PacketStream, PayloadBuilder};
use super::{
    CHARSET_UTF8MB4, CLIENT_DEPRECATE_EOF, CLIENT_PROTOCOL_41, CLIENT_TRANSACTIONS, Result,
};

/// `enum_field_types` values the honeypot emits.
pub mod column_type {
    pub const DECIMAL: u8 = 0x00;
    pub const LONG: u8 = 0x03;
    pub const DOUBLE: u8 = 0x05;
    pub const NULL: u8 = 0x06;
    pub const LONGLONG: u8 = 0x08;
    pub const DATETIME: u8 = 0x0c;
    pub const DATE: u8 = 0x0a;
    pub const BLOB: u8 = 0xfc;
    pub const VAR_STRING: u8 = 0xfd;
}

/// Column definition flags.
pub mod column_flags {
    pub const NOT_NULL: u16 = 0x0001;
    pub const PRI_KEY: u16 = 0x0002;
    pub const BINARY: u16 = 0x0080;
}

/// One `ColumnDefinition41` entry.
#[derive(Debug, Clone)]
pub struct ColumnDef<'a> {
    pub schema: &'a str,
    pub table: &'a str,
    pub org_table: &'a str,
    pub name: &'a str,
    pub org_name: &'a str,
    pub charset: u16,
    pub column_length: u32,
    pub column_type: u8,
    pub flags: u16,
    pub decimals: u8,
}

impl<'a> ColumnDef<'a> {
    /// A plain textual column, the shape most fake result sets need.
    pub fn text(schema: &'a str, table: &'a str, name: &'a str) -> Self {
        Self {
            schema,
            table,
            org_table: table,
            name,
            org_name: name,
            charset: u32::from(CHARSET_UTF8MB4) as u16,
            column_length: 1024,
            column_type: column_type::VAR_STRING,
            flags: 0,
            decimals: 0,
        }
    }

    /// A numeric column.
    pub fn number(schema: &'a str, table: &'a str, name: &'a str) -> Self {
        Self {
            schema,
            table,
            org_table: table,
            name,
            org_name: name,
            charset: 63,
            column_length: 21,
            column_type: column_type::LONGLONG,
            flags: column_flags::NOT_NULL,
            decimals: 0,
        }
    }
}

/// Build an `OK_Packet` payload.
pub fn ok_payload(
    capabilities: u32,
    affected_rows: u64,
    last_insert_id: u64,
    status: u16,
    warnings: u16,
) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(16);
    builder
        .u8(0x00)
        .lenenc_int(affected_rows)
        .lenenc_int(last_insert_id);
    if capabilities & CLIENT_PROTOCOL_41 != 0 {
        builder.u16le(status).u16le(warnings);
    } else if capabilities & CLIENT_TRANSACTIONS != 0 {
        builder.u16le(status);
    }
    builder.into_vec()
}

/// Build an `ERR_Packet` payload.
pub fn err_payload(capabilities: u32, code: u16, sqlstate: &str, message: &str) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(32 + message.len());
    builder.u8(0xff).u16le(code);
    if capabilities & CLIENT_PROTOCOL_41 != 0 {
        builder.u8(b'#');
        let mut state = *b"HY000";
        let raw = sqlstate.as_bytes();
        if raw.len() == 5 {
            state.copy_from_slice(raw);
        }
        builder.bytes(&state);
    }
    builder.bytes(message.as_bytes());
    builder.into_vec()
}

/// Build the packet that terminates a result set.
///
/// With `CLIENT_DEPRECATE_EOF` this is an OK packet carrying the `0xFE` header;
/// otherwise it is a classic `EOF_Packet`.
pub fn eof_payload(capabilities: u32, warnings: u16, status: u16) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(9);
    if capabilities & CLIENT_DEPRECATE_EOF != 0 {
        builder
            .u8(0xfe)
            .lenenc_int(0)
            .lenenc_int(0)
            .u16le(status)
            .u16le(warnings);
    } else {
        builder.u8(0xfe).u16le(warnings).u16le(status);
    }
    builder.into_vec()
}

/// Build the column count packet.
pub fn column_count_payload(count: usize) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(9);
    builder.lenenc_int(count as u64);
    builder.into_vec()
}

/// Build one `ColumnDefinition41` packet.
pub fn column_def_payload(column: &ColumnDef<'_>) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(96);
    builder
        .lenenc_str("def")
        .lenenc_str(column.schema)
        .lenenc_str(column.table)
        .lenenc_str(column.org_table)
        .lenenc_str(column.name)
        .lenenc_str(column.org_name)
        .lenenc_int(0x0c)
        .u16le(column.charset)
        .u32le(column.column_length)
        .u8(column.column_type)
        .u16le(column.flags)
        .u8(column.decimals)
        .zeros(2);
    builder.into_vec()
}

/// Build one text protocol row packet.
pub fn row_payload(values: &[Option<String>]) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(64);
    for value in values {
        builder.lenenc_opt(value.as_deref());
    }
    builder.into_vec()
}

/// Build an `AuthMoreData` packet (header `0x01`).
pub fn auth_more_data_payload(data: &[u8]) -> Vec<u8> {
    let mut builder = PayloadBuilder::with_capacity(1 + data.len());
    builder.u8(0x01).bytes(data);
    builder.into_vec()
}

/// Write a complete text protocol result set on `stream`.
pub async fn write_result_set<S>(
    stream: &mut PacketStream<S>,
    capabilities: u32,
    columns: &[ColumnDef<'_>],
    rows: &[Vec<Option<String>>],
    status: u16,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_packet(&column_count_payload(columns.len()))
        .await?;
    for column in columns {
        stream.write_packet(&column_def_payload(column)).await?;
    }
    if capabilities & CLIENT_DEPRECATE_EOF == 0 {
        stream
            .write_packet(&eof_payload(capabilities, 0, status))
            .await?;
    }
    for row in rows {
        stream.write_packet(&row_payload(row)).await?;
    }
    stream
        .write_packet(&eof_payload(capabilities, 0, status))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SERVER_STATUS_AUTOCOMMIT;
    use crate::protocol::packet::PayloadReader;

    #[test]
    fn ok_packet_shape() {
        let payload = ok_payload(CLIENT_PROTOCOL_41, 3, 0, SERVER_STATUS_AUTOCOMMIT, 0);
        let mut reader = PayloadReader::new(&payload);
        assert_eq!(reader.u8().expect("header"), 0x00);
        assert_eq!(reader.lenenc_int().expect("affected"), Some(3));
        assert_eq!(reader.lenenc_int().expect("insert id"), Some(0));
        assert_eq!(reader.u16le().expect("status"), SERVER_STATUS_AUTOCOMMIT);
        assert_eq!(reader.u16le().expect("warnings"), 0);
        assert!(reader.is_empty());
    }

    #[test]
    fn err_packet_carries_sqlstate() {
        let payload = err_payload(CLIENT_PROTOCOL_41, 1064, "42000", "syntax error");
        let mut reader = PayloadReader::new(&payload);
        assert_eq!(reader.u8().expect("header"), 0xff);
        assert_eq!(reader.u16le().expect("code"), 1064);
        assert_eq!(reader.u8().expect("marker"), b'#');
        assert_eq!(reader.take(5).expect("state"), b"42000");
        assert_eq!(reader.rest(), b"syntax error");
    }

    #[test]
    fn err_without_protocol41_omits_sqlstate() {
        let payload = err_payload(0, 1040, "08004", "too many");
        assert_eq!(payload[0], 0xff);
        assert!(!payload.windows(5).any(|w| w == b"42000"));
        assert!(payload.ends_with(b"too many"));
    }

    #[test]
    fn eof_switches_on_deprecate_eof() {
        let classic = eof_payload(CLIENT_PROTOCOL_41, 0, SERVER_STATUS_AUTOCOMMIT);
        assert_eq!(classic.len(), 5);
        assert_eq!(classic[0], 0xfe);

        let modern = eof_payload(
            CLIENT_PROTOCOL_41 | CLIENT_DEPRECATE_EOF,
            0,
            SERVER_STATUS_AUTOCOMMIT,
        );
        assert_eq!(modern[0], 0xfe);
        assert!(modern.len() > 5, "deprecated EOF is an OK packet");
    }

    #[test]
    fn column_definition_roundtrip() {
        let column = ColumnDef::text("app_prod", "users", "email");
        let payload = column_def_payload(&column);
        let mut reader = PayloadReader::new(&payload);
        assert_eq!(reader.lenenc_str().expect("catalog"), Some("def".into()));
        assert_eq!(
            reader.lenenc_str().expect("schema"),
            Some("app_prod".into())
        );
        assert_eq!(reader.lenenc_str().expect("table"), Some("users".into()));
        assert_eq!(
            reader.lenenc_str().expect("org table"),
            Some("users".into())
        );
        assert_eq!(reader.lenenc_str().expect("name"), Some("email".into()));
        assert_eq!(reader.lenenc_str().expect("org name"), Some("email".into()));
        assert_eq!(reader.lenenc_int().expect("fixed len"), Some(0x0c));
        assert_eq!(reader.u16le().expect("charset"), 45);
        assert_eq!(reader.u32le().expect("length"), 1024);
        assert_eq!(reader.u8().expect("type"), column_type::VAR_STRING);
        assert_eq!(reader.u16le().expect("flags"), 0);
        assert_eq!(reader.u8().expect("decimals"), 0);
        assert_eq!(reader.take(2).expect("filler"), &[0, 0]);
        assert!(reader.is_empty());
    }

    #[test]
    fn row_encodes_null_marker() {
        let row = vec![Some("1".to_string()), None, Some(String::new())];
        let payload = row_payload(&row);
        assert_eq!(payload, vec![0x01, b'1', 0xfb, 0x00]);
    }

    #[tokio::test]
    async fn result_set_frames_in_protocol_order() {
        let (client, server) = tokio::io::duplex(8192);
        let mut stream = PacketStream::new(server, 1 << 20);
        let mut client = PacketStream::new(client, 1 << 20);
        let columns = [
            ColumnDef::text("app_prod", "users", "id"),
            ColumnDef::text("app_prod", "users", "name"),
        ];
        let rows = vec![vec![Some("1".to_string()), Some("alice".to_string())]];

        write_result_set(
            &mut stream,
            CLIENT_PROTOCOL_41 | CLIENT_DEPRECATE_EOF,
            &columns,
            &rows,
            SERVER_STATUS_AUTOCOMMIT,
        )
        .await
        .expect("write");

        let count = client.read_packet().await.expect("column count");
        assert_eq!(count, vec![0x02]);
        let first_col = client.read_packet().await.expect("col 1");
        assert_eq!(first_col[0], 0x03, "column def starts with 'def' length");
        let _second_col = client.read_packet().await.expect("col 2");
        let row = client.read_packet().await.expect("row");
        assert_eq!(row[0], 0x01, "first value is a 1 byte string");
        let terminator = client.read_packet().await.expect("terminator");
        assert_eq!(terminator[0], 0xfe, "DEPRECATE_EOF terminator");
    }

    #[tokio::test]
    async fn result_set_with_classic_eof_emits_extra_terminator() {
        let (client, server) = tokio::io::duplex(8192);
        let mut stream = PacketStream::new(server, 1 << 20);
        let mut client = PacketStream::new(client, 1 << 20);
        let columns = [ColumnDef::number("", "", "1")];
        let rows = vec![vec![Some("1".to_string())]];
        write_result_set(
            &mut stream,
            CLIENT_PROTOCOL_41,
            &columns,
            &rows,
            SERVER_STATUS_AUTOCOMMIT,
        )
        .await
        .expect("write");

        let mut packets = Vec::new();
        for _ in 0..5 {
            packets.push(client.read_packet().await.expect("packet"));
        }
        assert_eq!(packets[0], vec![0x01], "column count");
        assert_eq!(
            packets[2],
            vec![0xfe, 0x00, 0x00, 0x02, 0x00],
            "eof after defs"
        );
        assert_eq!(packets[4][0], 0xfe, "closing eof");
    }
}
