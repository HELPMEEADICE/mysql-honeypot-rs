// SPDX-License-Identifier: GPL-3.0-only
//! Fuzz target: the TOML configuration loader.
//!
//! The input is decoded lossily to text and handed to `Config::from_toml`, which
//! parses with `serde` and then clamps every field in `Config::sanitize`.
//!
//! Invariants asserted:
//!   * hostile TOML never panics — a `ConfigError` is a correct answer;
//!   * a successfully parsed config is already clamped, so every downstream
//!     consumer can rely on the ranges below without re-checking them;
//!   * in particular `1 <= server.max_connections <= 65_535`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mysql_honeypot_rs::config::Config;

fuzz_target!(|data: &[u8]| {
    // TOML is text: the loader reads a file with `read_to_string`, and a lossy
    // conversion is the closest in-memory equivalent for arbitrary bytes.
    let text = String::from_utf8_lossy(data);

    let Ok(config) = Config::from_toml(&text) else {
        // Malformed or schema-mismatched documents are rejected, never fatal.
        return;
    };

    // ---- `[server]` ---------------------------------------------------------
    assert!(
        (1..=65_535).contains(&config.server.max_connections),
        "max_connections out of range: {}",
        config.server.max_connections
    );
    assert!(
        (4_096..=64 * 1024 * 1024).contains(&config.server.max_packet_size),
        "max_packet_size out of range: {}",
        config.server.max_packet_size
    );
    assert!(
        (64..=1024 * 1024).contains(&config.server.max_sql_length),
        "max_sql_length out of range: {}",
        config.server.max_sql_length
    );
    assert!(
        (5..=86_400).contains(&config.server.idle_timeout_seconds),
        "idle_timeout_seconds out of range: {}",
        config.server.idle_timeout_seconds
    );
    assert!(
        (1..=300).contains(&config.server.handshake_timeout_seconds),
        "handshake_timeout_seconds out of range: {}",
        config.server.handshake_timeout_seconds
    );
    assert!(
        (0..=120).contains(&config.server.shutdown_grace_seconds),
        "shutdown_grace_seconds out of range: {}",
        config.server.shutdown_grace_seconds
    );
    assert!(
        !config.server.host.trim().is_empty(),
        "host must fall back to a default"
    );
    assert!(
        !config.server.version.trim().is_empty(),
        "version must fall back to a default"
    );

    // ---- `[authentication]` ------------------------------------------------
    assert!(
        config.authentication.delay_min_ms >= 1,
        "a zero delay defeats the trap"
    );
    assert!(
        config.authentication.delay_min_ms <= config.authentication.delay_max_ms,
        "inverted delay bounds must be swapped by sanitize()"
    );

    // ---- `[database]` ------------------------------------------------------
    assert!(
        (16..=1_048_576).contains(&config.database.queue_capacity),
        "queue_capacity out of range: {}",
        config.database.queue_capacity
    );
    assert!(
        (50..=60_000).contains(&config.database.busy_timeout_ms),
        "busy_timeout_ms out of range: {}",
        config.database.busy_timeout_ms
    );
    assert!(
        !config.sqlite_path().trim().is_empty(),
        "sqlite_path needs a default"
    );

    // ---- `[logging]` -------------------------------------------------------
    assert!(
        !config.logging.level.trim().is_empty(),
        "level must fall back to a default"
    );
});
