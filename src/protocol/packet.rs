// SPDX-License-Identifier: GPL-3.0-only
//! MySQL packet framing, length-encoded primitives and payload builders.
//!
//! Every MySQL packet on the wire is `3-byte little endian length | 1-byte
//! sequence id | payload`. Payloads of `0xFF_FFFF` bytes are followed by a
//! continuation packet, so a logical payload may span several frames.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Error, Result};

/// Largest payload a single frame can carry (`2^24 - 1`).
pub const MAX_CHUNK_SIZE: usize = 0x00FF_FFFF;

/// A sequence-aware, size-capped MySQL packet stream.
///
/// The sequence id is shared between reads and writes because the protocol
/// numbers a whole exchange continuously: the client sends sequence `0`, the
/// server answers `1, 2, ...`, and the next command starts again at `0`.
pub struct PacketStream<S> {
    io: S,
    sequence: u8,
    max_payload: usize,
}

impl<S> PacketStream<S> {
    /// Wrap an I/O object, capping any single logical payload at `max_payload`.
    pub fn new(io: S, max_payload: usize) -> Self {
        Self {
            io,
            sequence: 0,
            max_payload: max_payload.max(1024),
        }
    }

    /// The sequence id the next packet is expected to carry / will use.
    pub fn sequence(&self) -> u8 {
        self.sequence
    }

    /// Force the sequence id (a fresh client command always starts at `0`).
    pub fn set_sequence(&mut self, sequence: u8) {
        self.sequence = sequence;
    }

    /// Consume the wrapper and return the underlying transport.
    pub fn into_inner(self) -> S {
        self.io
    }
}

impl<S: AsyncRead + Unpin> PacketStream<S> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        // tokio's `read_exact` yields the byte count; only success matters here.
        self.io
            .read_exact(buf)
            .await
            .map(|_filled| ())
            .map_err(Error::from)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> PacketStream<S> {
    /// Read one logical payload, joining continuation frames.
    pub async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut payload: Vec<u8> = Vec::new();
        loop {
            let mut header = [0u8; 4];
            self.read_exact(&mut header).await?;
            let len = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
            // Adopt whatever the peer used: a strict mismatch check would let
            // any broken scanner kill the session it is supposed to keep open.
            self.sequence = header[3].wrapping_add(1);
            if len > self.max_payload || payload.len() + len > self.max_payload {
                return Err(Error::PacketTooLarge {
                    len: payload.len() + len,
                    max: self.max_payload,
                });
            }
            let start = payload.len();
            payload.resize(start + len, 0);
            if len > 0 {
                self.read_exact(&mut payload[start..]).await?;
            }
            if len < MAX_CHUNK_SIZE {
                return Ok(payload);
            }
        }
    }

    /// Write one logical payload, splitting it into frames when oversized.
    pub async fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        loop {
            let chunk = (payload.len() - offset).min(MAX_CHUNK_SIZE);
            let header = [
                (chunk & 0xff) as u8,
                ((chunk >> 8) & 0xff) as u8,
                ((chunk >> 16) & 0xff) as u8,
                self.sequence,
            ];
            self.sequence = self.sequence.wrapping_add(1);
            self.io.write_all(&header).await.map_err(Error::Io)?;
            if chunk > 0 {
                self.io
                    .write_all(&payload[offset..offset + chunk])
                    .await
                    .map_err(Error::Io)?;
            }
            offset += chunk;
            if chunk < MAX_CHUNK_SIZE {
                break;
            }
        }
        self.io.flush().await.map_err(Error::Io)
    }
}

// ---------------------------------------------------------------------------
// Length-encoded primitives
// ---------------------------------------------------------------------------

/// Number of bytes `value` occupies when length-encoded.
pub fn lenenc_int_len(value: u64) -> usize {
    match value {
        0..=250 => 1,
        251..=65_535 => 3,
        65_536..=16_777_215 => 4,
        _ => 9,
    }
}

/// Append a length-encoded integer.
pub fn push_lenenc_int(buf: &mut Vec<u8>, value: u64) {
    match value {
        0..=250 => buf.push(value as u8),
        251..=65_535 => {
            buf.push(0xfc);
            buf.extend_from_slice(&(value as u16).to_le_bytes());
        }
        65_536..=16_777_215 => {
            buf.push(0xfd);
            let bytes = (value as u32).to_le_bytes();
            buf.extend_from_slice(&bytes[..3]);
        }
        _ => {
            buf.push(0xfe);
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Append a length-encoded string.
pub fn push_lenenc_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    push_lenenc_int(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// Incremental payload builder used by every response encoder.
#[derive(Debug, Default, Clone)]
pub struct PayloadBuilder {
    buf: Vec<u8>,
}

impl PayloadBuilder {
    /// Empty builder.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Empty builder with a pre-allocated payload buffer.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Append one byte.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Append a little endian `u16`.
    pub fn u16le(&mut self, value: u16) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a little endian `u32`.
    pub fn u32le(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append raw bytes.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Append a NUL terminated string.
    pub fn nul_str(&mut self, value: &str) -> &mut Self {
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
        self
    }

    /// Append a length-encoded integer.
    pub fn lenenc_int(&mut self, value: u64) -> &mut Self {
        push_lenenc_int(&mut self.buf, value);
        self
    }

    /// Append a length-encoded string.
    pub fn lenenc_str(&mut self, value: &str) -> &mut Self {
        push_lenenc_bytes(&mut self.buf, value.as_bytes());
        self
    }

    /// Append a length-encoded byte string, or the `NULL` marker.
    pub fn lenenc_opt(&mut self, value: Option<&str>) -> &mut Self {
        match value {
            Some(text) => self.lenenc_str(text),
            None => {
                self.buf.push(0xfb);
                self
            }
        }
    }

    /// Append `count` zero bytes.
    pub fn zeros(&mut self, count: usize) -> &mut Self {
        self.buf.resize(self.buf.len() + count, 0);
        self
    }

    /// Current payload length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Finish the payload.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Bounds-checked reader for client supplied payloads.
///
/// Every accessor returns an error instead of panicking, which is what keeps a
/// hostile scanner from taking the process down with a truncated packet.
pub struct PayloadReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PayloadReader<'a> {
    /// Wrap a payload slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Offset of the read cursor.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes left to read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Whether the payload is exhausted.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take `len` bytes.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::Malformed("offset overflow"))?;
        if end > self.data.len() {
            return Err(Error::Malformed("truncated payload"));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Skip `len` bytes.
    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.take(len).map(|_| ())
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a little endian `u16`.
    pub fn u16le(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little endian `u32`.
    pub fn u32le(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a NUL terminated string, tolerating invalid UTF-8.
    pub fn nul_str(&mut self) -> Result<String> {
        let rest = &self.data[self.pos..];
        match rest.iter().position(|b| *b == 0) {
            Some(idx) => {
                let text = String::from_utf8_lossy(&rest[..idx]).into_owned();
                self.pos += idx + 1;
                Ok(text)
            }
            None => {
                // Unterminated: consume the remainder rather than failing, so a
                // slightly off client still reaches the authentication trap.
                let text = String::from_utf8_lossy(rest).into_owned();
                self.pos = self.data.len();
                Ok(text)
            }
        }
    }

    /// Read a length-encoded integer; `Ok(None)` is the `NULL` marker.
    pub fn lenenc_int(&mut self) -> Result<Option<u64>> {
        let first = self.u8()?;
        match first {
            0xfb => Ok(None),
            0xfc => Ok(Some(u16::from_le_bytes([self.u8()?, self.u8()?]) as u64)),
            0xfd => {
                let bytes = self.take(3)?;
                Ok(Some(
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as u64
                ))
            }
            0xfe => {
                let bytes = self.take(8)?;
                let mut raw = [0u8; 8];
                raw.copy_from_slice(bytes);
                Ok(Some(u64::from_le_bytes(raw)))
            }
            0xff => Err(Error::Malformed("invalid length-encoded integer")),
            other => Ok(Some(other as u64)),
        }
    }

    /// Read a length-encoded string; `Ok(None)` is the `NULL` marker.
    pub fn lenenc_bytes(&mut self) -> Result<Option<&'a [u8]>> {
        match self.lenenc_int()? {
            None => Ok(None),
            Some(len) => Ok(Some(self.take(len as usize)?)),
        }
    }

    /// Read a length-encoded string as text, tolerating invalid UTF-8.
    pub fn lenenc_str(&mut self) -> Result<Option<String>> {
        match self.lenenc_bytes()? {
            None => Ok(None),
            Some(bytes) => Ok(Some(String::from_utf8_lossy(bytes).into_owned())),
        }
    }

    /// Consume and return everything that is left.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.pos..];
        self.pos = self.data.len();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenenc_int_roundtrip() {
        let cases = [
            0u64,
            1,
            250,
            251,
            65_535,
            65_536,
            16_777_215,
            16_777_216,
            u64::MAX,
        ];
        for value in cases {
            let mut buf = Vec::new();
            push_lenenc_int(&mut buf, value);
            assert_eq!(
                buf.len(),
                lenenc_int_len(value),
                "size mismatch for {value}"
            );
            let mut reader = PayloadReader::new(&buf);
            assert_eq!(reader.lenenc_int().expect("decode"), Some(value));
            assert_eq!(reader.remaining(), 0);
        }
    }

    #[test]
    fn lenenc_null_marker() {
        let mut reader = PayloadReader::new(&[0xfb]);
        assert_eq!(reader.lenenc_int().expect("decode"), None);
    }

    #[test]
    fn truncated_length_encoded_string_errors() {
        // Declares 5 bytes but only 2 follow.
        let mut reader = PayloadReader::new(&[0x05, b'a', b'b']);
        assert!(reader.lenenc_bytes().is_err());
    }

    #[test]
    fn nul_str_handles_unterminated_tail() {
        let mut reader = PayloadReader::new(b"root");
        assert_eq!(reader.nul_str().expect("read"), "root");
        assert!(reader.is_empty());
    }

    #[tokio::test]
    async fn packet_roundtrip_over_duplex() {
        let (client, server) = tokio::io::duplex(4096);
        let mut writer = PacketStream::new(client, 1 << 20);
        let mut reader = PacketStream::new(server, 1 << 20);

        writer.set_sequence(0);
        writer.write_packet(b"hello").await.expect("write");
        let payload = reader.read_packet().await.expect("read");
        assert_eq!(payload, b"hello");
        assert_eq!(reader.sequence(), 1);
    }

    #[tokio::test]
    async fn empty_payload_is_a_valid_packet() {
        let (client, server) = tokio::io::duplex(64);
        let mut writer = PacketStream::new(client, 1024);
        let mut reader = PacketStream::new(server, 1024);
        writer.write_packet(b"").await.expect("write");
        assert_eq!(reader.read_packet().await.expect("read"), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn oversized_declared_length_is_rejected() {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = tokio::io::duplex(64);
        let mut reader = PacketStream::new(server, 4096);
        // Header claims 1 MiB, which exceeds the 4 KiB cap.
        let header: [u8; 4] = [0x00, 0x00, 0x10, 0x00];
        client.write_all(&header).await.expect("write header");
        match reader.read_packet().await {
            Err(Error::PacketTooLarge { .. }) => {}
            other => panic!("expected PacketTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn eof_at_boundary_is_reported_as_eof() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let mut reader = PacketStream::new(server, 1024);
        match reader.read_packet().await {
            Err(Error::Eof) => {}
            other => panic!("expected Eof, got {other:?}"),
        }
    }
}
