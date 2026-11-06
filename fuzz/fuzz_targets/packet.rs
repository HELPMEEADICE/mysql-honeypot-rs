// SPDX-License-Identifier: GPL-3.0-only
//! Fuzz target: the bounds checked payload reader.
//!
//! Surfaces exercised on the same bytes:
//!   * `PayloadReader` — every accessor, in a fixed order, ignoring failures.
//!   * `truncate_to` — byte bounded truncation, with the input read as text.
//!
//! Invariants asserted:
//!   * no accessor panics: returning `Err` is the contract, panicking is the bug;
//!   * the cursor never moves backwards and never passes the end of the payload;
//!   * `remaining()` always equals `data.len() - position()`;
//!   * `rest()` consumes the reader exactly once and returns a payload suffix;
//!   * `truncate_to` never splits a UTF-8 character and never exceeds its cap.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mysql_honeypot_rs::protocol::packet::PayloadReader;
use mysql_honeypot_rs::util::truncate_to;

/// Hard cap on the accessor rounds. The cursor only ever moves forward, so this
/// cap is belt and braces rather than the actual termination argument.
const MAX_ROUNDS: usize = 32;

fuzz_target!(|data: &[u8]| {
    let mut reader = PayloadReader::new(data);
    assert_eq!(reader.position(), 0, "a fresh reader starts at offset 0");
    assert_eq!(
        reader.remaining(),
        data.len(),
        "a fresh reader owns all bytes"
    );
    assert_eq!(reader.is_empty(), data.is_empty());

    let mut last_position = 0usize;
    for _ in 0..MAX_ROUNDS {
        // Every accessor runs on every round. Failures are expected and
        // deliberately ignored; only a panic would be a finding.
        let _ = reader.u8();
        let _ = reader.u16le();
        let _ = reader.u32le();
        let _ = reader.nul_str();
        let _ = reader.lenenc_int();
        let _ = reader.lenenc_bytes();
        let _ = reader.lenenc_str();
        let _ = reader.take(0);
        let _ = reader.take(1);
        // Offset overflow must be an error, never a wrapping add.
        let _ = reader.take(usize::MAX);
        let _ = reader.skip(3);
        let _ = reader.skip(data.len());

        let position = reader.position();
        assert!(
            position <= data.len(),
            "cursor ran past the end of the payload"
        );
        assert!(position >= last_position, "cursor moved backwards");
        assert_eq!(
            reader.remaining(),
            data.len() - position,
            "remaining() disagrees with the cursor"
        );
        assert_eq!(reader.is_empty(), position == data.len());
        if position == last_position {
            break;
        }
        last_position = position;
    }

    // `rest()` is the one accessor that cannot fail; it must consume everything
    // and return the untouched suffix of the input.
    let tail = reader.rest();
    assert!(reader.is_empty(), "rest() must exhaust the reader");
    assert_eq!(reader.position(), data.len(), "rest() must land on the end");
    assert!(tail.len() <= data.len(), "rest() cannot invent bytes");
    assert!(
        data.ends_with(tail),
        "rest() must return a suffix of the payload"
    );
    let _ = reader.u8(); // one read past the end: still an error, never a panic
    assert!(
        reader.is_empty(),
        "a failed read must not refill the payload"
    );

    // ------------------------------------------------------------------
    // Same bytes, second surface: byte bounded truncation.
    // ------------------------------------------------------------------
    let original = String::from_utf8_lossy(data);
    let cap = data.len() / 2;
    let (text, truncated) = truncate_to(&original, cap);
    assert!(
        original.starts_with(&text),
        "truncate_to must return a prefix"
    );
    assert!(
        text.is_char_boundary(text.len()),
        "truncate_to split a UTF-8 character"
    );
    assert!(
        !truncated || text.len() <= cap,
        "truncation exceeded its byte cap"
    );
    assert!(
        truncated || text.len() == original.len(),
        "an untruncated result must be the whole text"
    );
    // A wider budget may never yield a shorter string.
    let (wider, _) = truncate_to(&original, cap.saturating_add(1));
    assert!(wider.len() >= text.len(), "a wider cap truncated more");
    // A zero budget is always safe, including on a multi-byte character.
    let (empty, _) = truncate_to(&original, 0);
    assert!(
        empty.is_empty(),
        "a zero byte cap must yield an empty string"
    );
});
