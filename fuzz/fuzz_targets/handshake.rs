// SPDX-License-Identifier: GPL-3.0-only
//! Fuzz target: the 4.1 handshake response parser.
//!
//! Invariants asserted:
//!   * `is_ssl_request` is total (it answers for any length, including zero) and
//!     mirrors the `CLIENT_SSL` bit of the leading capability word;
//!   * an accepted response always carries the whole 32 byte fixed header, so the
//!     capability word, `max_packet_size` and `charset` round-trip verbatim;
//!   * `attrs.len() <= 32` — the parser refuses to grow the log entry without
//!     bound, so a hostile client cannot buy memory with a long attribute list;
//!   * no parsed field is longer than the payload it was read from.
//!
//! The input is never indexed with a fuzz controlled index: every access goes
//! through `get()`, and the fixed offsets used here are compile time constants.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mysql_honeypot_rs::protocol::CLIENT_SSL;
use mysql_honeypot_rs::protocol::handshake::{is_ssl_request, parse_handshake_response};

/// The parser caps the connect-attribute list at this many key/value pairs.
const MAX_ATTRS: usize = 32;

/// A `HandshakeResponse41` must carry a 32 byte fixed header block.
const MIN_HEADER: usize = 32;

/// Little endian `u32` at a fixed offset, or `None` when the input is shorter.
fn le_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let head: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(head))
}

fuzz_target!(|data: &[u8]| {
    // Total predicate: it must answer for any length and must not read past the
    // end of a short payload.
    let tls = is_ssl_request(data);
    match le_u32_at(data, 0) {
        Some(capabilities) => assert_eq!(
            tls,
            capabilities & CLIENT_SSL != 0,
            "is_ssl_request must mirror the CLIENT_SSL bit"
        ),
        None => assert!(!tls, "a payload under 4 bytes cannot request TLS"),
    }

    let Ok(response) = parse_handshake_response(data) else {
        // Rejection is a first class, non-panicking outcome: nothing to check.
        return;
    };

    // ---- invariants that hold for every accepted handshake response ---------
    assert!(
        data.len() >= MIN_HEADER,
        "an accepted response is at least {MIN_HEADER} bytes"
    );

    // Capabilities round-trip: the parser must not invent or mask flags.
    assert_eq!(
        Some(response.capabilities),
        le_u32_at(data, 0),
        "capabilities must round-trip verbatim"
    );
    assert_eq!(
        Some(response.max_packet_size),
        le_u32_at(data, 4),
        "max_packet_size must round-trip verbatim"
    );
    assert_eq!(
        Some(response.charset),
        data.get(8).copied(),
        "charset must round-trip verbatim"
    );
    assert!(
        (response.capabilities & CLIENT_SSL != 0) == tls,
        "the parsed capability word must agree with is_ssl_request"
    );

    // The attribute list is the only variable length collection kept.
    assert!(
        response.attrs.len() <= MAX_ATTRS,
        "attribute list must stay bounded, got {}",
        response.attrs.len()
    );

    // No parsed field may be longer than the payload it came from.
    let bound = data.len();
    assert!(
        response.username.len() <= bound,
        "username grew beyond the input"
    );
    assert!(
        response.auth_response.len() <= bound,
        "auth_response grew beyond the input"
    );
    assert!(
        response
            .database
            .as_ref()
            .is_none_or(|db| db.len() <= bound),
        "database grew beyond the input"
    );
    assert!(
        response
            .auth_plugin
            .as_ref()
            .is_none_or(|p| p.len() <= bound),
        "auth_plugin grew beyond the input"
    );
    for (key, value) in &response.attrs {
        assert!(key.len() <= bound, "an attribute key grew beyond the input");
        assert!(
            value.len() <= bound,
            "an attribute value grew beyond the input"
        );
    }

    // `client_summary()` runs on the accepted path in the real honeypot, so it
    // must survive hostile attribute contents too.
    let _ = response.client_summary();
});
