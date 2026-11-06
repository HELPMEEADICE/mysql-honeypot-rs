// SPDX-License-Identifier: GPL-3.0-only
//! Fuzz target: MySQL packet framing over an in-memory duplex stream.
//!
//! The input is written into one half of a `tokio::io::duplex` pair and read
//! back through `PacketStream::read_packet()`, so the 3-byte length header, the
//! sequence id adoption and the payload cap are all driven by fuzz bytes.
//!
//! Invariants asserted:
//!   * `read_packet()` always terminates and always yields a `Result`;
//!   * an accepted payload never exceeds the configured 1 MiB cap;
//!   * the number of reads per iteration is bounded, so a hostile stream cannot
//!     keep this body spinning, and the writer task is aborted, never awaited.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mysql_honeypot_rs::protocol::packet::PacketStream;
use tokio::io::{AsyncWriteExt, duplex};

/// 1 MiB — the shipped `server.max_packet_size` default, and the cap this
/// harness configures on the stream it fuzzes.
const MAX_PAYLOAD: usize = 1 << 20;

/// 1 MiB — never hand more than this to the duplex writer, so a single
/// iteration cannot allocate without bound.
const MAX_INPUT: usize = 1 << 20;

/// In-memory pipe capacity. Deliberately smaller than `MAX_INPUT`: the writer
/// task must be able to block on a full buffer, which is exactly the case the
/// abort at the end of the body exists to handle.
const DUPLEX_CAPACITY: usize = 64 * 1024;

/// Hard cap on the number of packets read in one iteration.
const MAX_READS: usize = 4;

fuzz_target!(|data: &[u8]| {
    // The spawned writer must be `'static`, so the bytes are copied once.
    let input = data[..data.len().min(MAX_INPUT)].to_vec();

    // A current thread runtime is enough: `tokio::io::duplex` is purely
    // in-memory and registers with no reactor, so no I/O and no timer driver is
    // enabled here. That is also what keeps this harness from opening sockets.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() else {
        return; // no runtime to drive: nothing to exercise, and nothing to panic on
    };

    runtime.block_on(async move {
        let (mut writer, reader) = duplex(DUPLEX_CAPACITY);
        let mut stream = PacketStream::new(reader, MAX_PAYLOAD);

        // The writer is its own task so that a full duplex buffer parks it
        // instead of blocking the reading task. It is aborted after the read
        // loop and never awaited, so a reader that stops early cannot deadlock
        // this body; dropping the write half gives the reader its EOF.
        let writer_task = tokio::spawn(async move {
            let _ = writer.write_all(&input).await;
            drop(writer);
        });

        // Termination: `read_packet()` returns on the first frame whose declared
        // length is not `MAX_CHUNK_SIZE`, and any frame above `MAX_PAYLOAD` is
        // rejected outright — with a 1 MiB cap no frame can ever ask for a
        // continuation. `MAX_READS` bounds the loop on top of that.
        let mut reads = 0usize;
        while reads < MAX_READS {
            match stream.read_packet().await {
                Ok(payload) => {
                    assert!(
                        payload.len() <= MAX_PAYLOAD,
                        "read_packet() assembled {} bytes past the cap",
                        payload.len()
                    );
                    reads += 1;
                }
                // EOF, an oversized frame and a truncated frame are all ordinary
                // outcomes. What this harness proves is that we got a `Result`
                // back instead of a panic or a hang.
                Err(_) => break,
            }
        }

        writer_task.abort();
        drop(writer_task);
    });
});
