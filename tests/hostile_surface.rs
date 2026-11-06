// SPDX-License-Identifier: GPL-3.0-only
//! A deterministic stand-in for the `cargo-fuzz` harnesses in `fuzz/`.
//!
//! The real harnesses need a nightly toolchain and `cargo-fuzz`, which is not
//! something every build host has. This file replays the same invariants over a
//! generated corpus with a fixed seed, so `cargo test` covers the hostile-input
//! surface on the stable toolchain and a regression shows up as a failing test
//! rather than as a fuzz finding nobody runs.
//!
//! What is exercised, mirroring `fuzz/fuzz_targets/`:
//!
//! * `PayloadReader` — every accessor, every invariant about the cursor;
//! * `parse_handshake_response` — bounded fields, total predicates;
//! * `PacketStream::read_packet` — framing, the payload cap, termination;
//! * `Config::from_toml` — hostile TOML never panics and is always clamped;
//! * `fakedb::dispatch` — mutated SQL never panics and never breaks the
//!   session's accounting.
//!
//! The release profile is `panic = "abort"`, so a panic here is not a test
//! failure: it takes the whole process down. These cases are the cheapest proof
//! that hostile input cannot do that.

use mysql_honeypot_rs::config::Config;
use mysql_honeypot_rs::fakedb::{FakeDatabase, QueryContext, SessionState};
use mysql_honeypot_rs::protocol::handshake::parse_handshake_response;
use mysql_honeypot_rs::protocol::packet::{PacketStream, PayloadReader};
use tokio::io::AsyncWriteExt;

/// Small deterministic PRNG: xorshift64*, so a failure is reproducible from the
/// seed printed in the assertion message.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }

    /// A value in `0..bound`, or `0` for a zero bound.
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len.saturating_add(1));
        (0..len).map(|_| self.next_u8()).collect()
    }
}

#[test]
fn payload_reader_survives_hostile_bytes() {
    let mut rng = Rng::new(0x5EED_1234);
    for round in 0..2_000 {
        let data = rng.bytes(64);
        let mut reader = PayloadReader::new(&data);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.remaining(), data.len());
        let mut last = 0usize;
        for _ in 0..16 {
            // Every accessor runs; only a panic would be a finding.
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

            let position = reader.position();
            assert!(
                position <= data.len(),
                "round {round}: cursor ran past the end"
            );
            assert!(position >= last, "round {round}: cursor moved backwards");
            assert_eq!(
                reader.remaining(),
                data.len() - position,
                "round {round}: remaining() disagrees with the cursor"
            );
            if position == last {
                break;
            }
            last = position;
        }
        let tail = reader.rest();
        assert!(reader.is_empty());
        assert!(data.ends_with(tail), "round {round}: rest() invented bytes");
        let _ = reader.u8();
        assert!(reader.is_empty(), "a failed read must not refill");
    }
}

#[test]
fn handshake_parsing_survives_hostile_bytes() {
    let mut rng = Rng::new(0xC0FF_EE42);
    for round in 0..2_000 {
        let data = rng.bytes(96);
        // `is_ssl_request` is total: it must answer for any length.
        let tls = mysql_honeypot_rs::protocol::handshake::is_ssl_request(&data);
        let Ok(response) = parse_handshake_response(&data) else {
            continue;
        };
        let bound = data.len();
        assert!(
            data.len() >= 32,
            "round {round}: an accepted response is at least 32 bytes"
        );
        // The name fields go through `String::from_utf8_lossy`, so one invalid
        // byte becomes the three byte replacement character: the parser may
        // amplify by at most 3x, never more. The session then clips the name to
        // `LOG_USERNAME_LIMIT` before storing it, which is what actually bounds
        // the long lived allocation.
        assert!(
            response.username.len() <= bound.saturating_mul(3),
            "round {round}: username grew past the 3x of a lossy conversion"
        );
        assert!(
            response.auth_response.len() <= bound,
            "round {round}: auth response grew beyond the input"
        );
        assert!(
            response.attrs.len() <= 32,
            "round {round}: the attribute list is unbounded"
        );
        for (key, value) in &response.attrs {
            assert!(key.len() <= bound.saturating_mul(3) && value.len() <= bound.saturating_mul(3));
        }
        if data.len() >= 4 {
            assert_eq!(
                tls,
                response.capabilities & mysql_honeypot_rs::protocol::CLIENT_SSL != 0,
                "round {round}: is_ssl_request disagrees with the parsed flags"
            );
        }
        // Runs on the accepted path in the server, so it must survive too.
        let _ = response.client_summary();
    }
}

#[tokio::test]
async fn packet_framing_survives_hostile_bytes() {
    const MAX_PAYLOAD: usize = 1 << 20;
    let mut rng = Rng::new(0xABBA_9876);
    for round in 0..200 {
        let input = rng.bytes(4_096);
        let (mut writer, reader) = tokio::io::duplex(8 * 1024);
        let mut stream = PacketStream::new(reader, MAX_PAYLOAD);
        let copy = input.clone();
        let writer_task = tokio::spawn(async move {
            let _ = writer.write_all(&copy).await;
            drop(writer);
        });
        for _ in 0..4 {
            match stream.read_packet().await {
                Ok(payload) => assert!(
                    payload.len() <= MAX_PAYLOAD,
                    "round {round}: read_packet assembled {} bytes past the cap",
                    payload.len()
                ),
                Err(_) => break,
            }
        }
        writer_task.abort();
        drop(writer_task);
    }
}

#[test]
fn hostile_toml_never_panics_and_is_always_clamped() {
    let mut rng = Rng::new(0x1357_2468);
    // Real fragments plus random bytes, so the parser sees both shapes.
    let fragments = [
        "[server]\n",
        "port = 0\n",
        "max_connections = 999999999\n",
        "max_packet_size = 1\n",
        "max_sql_length = 0\n",
        "idle_timeout_seconds = 4294967295\n",
        "bogus_field = true\n",
        "[database]\nretention_days = 999999999\n",
        "max_size_bytes = 18446744073709551615\n",
        "queue_capacity = 0\n",
        "[authentication]\ndelay_min_ms = 9000\ndelay_max_ms = 1\n",
        "[virtualdb]\nmax_tombstones = 0\nmax_columns_per_table = 0\n",
        "\u{0000}",
        "]]][[[",
    ];
    for round in 0..1_000 {
        let mut text = String::new();
        let pieces = 1 + rng.below(6);
        for _ in 0..pieces {
            if rng.below(3) == 0 {
                text.push_str(&String::from_utf8_lossy(&rng.bytes(24)));
            } else {
                text.push_str(fragments[rng.below(fragments.len())]);
            }
        }
        let Ok(config) = Config::from_toml(&text) else {
            continue;
        };
        // Whatever parsed must already be clamped; downstream code relies on it.
        assert!(
            (1..=65_535).contains(&config.server.max_connections),
            "round {round}: max_connections out of range"
        );
        assert!(
            (4_096..=64 * 1024 * 1024).contains(&config.server.max_packet_size),
            "round {round}: max_packet_size out of range"
        );
        assert!(
            config.authentication.delay_min_ms >= 1
                && config.authentication.delay_min_ms <= config.authentication.delay_max_ms,
            "round {round}: the delay window was not clamped"
        );
        assert!(
            !config.server.host.trim().is_empty(),
            "round {round}: host has no default"
        );
    }
}

#[test]
fn mutated_sql_never_breaks_the_session() {
    let database = FakeDatabase::new("8.0.36");
    let context = QueryContext::new(
        "app_prod".to_string(),
        "root".to_string(),
        "203.0.113.9".to_string(),
        7,
        "8.0.36".to_string(),
    );
    let mut state = SessionState::default();
    let mut rng = Rng::new(0x0BAD_F00D);

    // Statement shapes worth mutating: each one exercises a different executor.
    let seeds = [
        "SELECT username FROM app_prod.users WHERE id = 1 ORDER BY username LIMIT 2",
        "SELECT role, COUNT(*) FROM app_prod.users GROUP BY role HAVING COUNT(*) > 0",
        "INSERT INTO app_prod.users (username, role) VALUES ('x', 'y')",
        "UPDATE app_prod.users SET role = 'z' WHERE id = 2",
        "DELETE FROM app_prod.users WHERE id = 3 LIMIT 1",
        "REPLACE INTO app_prod.users (id, username) VALUES (1, 'root')",
        "CREATE TABLE app_prod.t (id bigint, name varchar(32))",
        "DROP TABLE app_prod.t",
        "TRUNCATE TABLE app_prod.users",
        "SHOW COLUMNS FROM app_prod.users",
        "SELECT SUBSTRING(username, 1, 1e300) FROM app_prod.users",
    ];
    let alphabet: &[u8] = b"'\"`?%()[]-=<>,.@#/*\\;\x00\x1b\xf0\x9f\x98\x80";

    for round in 0..3_000usize {
        let mut text = seeds[rng.below(seeds.len())].as_bytes().to_vec();
        // A handful of single-byte mutations: insert, delete or replace.
        let edits = 1 + rng.below(4);
        for _ in 0..edits {
            if text.is_empty() {
                break;
            }
            let index = rng.below(text.len());
            match rng.below(3) {
                0 => text.insert(index, alphabet[rng.below(alphabet.len())]),
                1 => {
                    text.remove(index);
                }
                _ => text[index] = alphabet[rng.below(alphabet.len())],
            }
        }
        let sql = String::from_utf8_lossy(&text).into_owned();
        // Any answer is acceptable; not returning is not.
        let _ = database.dispatch(&sql, &context, &mut state);

        // The session's accounting has to survive every single one of them.
        let (rows, bytes) = state.recount();
        assert_eq!(state.rows(), rows, "round {round}: row counter drifted");
        assert_eq!(state.bytes(), bytes, "round {round}: byte counter drifted");
        assert!(
            state.tombstones() <= state.budgets().max_tombstones,
            "round {round}: tombstone budget breached"
        );
        assert!(
            state.bytes() <= state.budgets().max_total_bytes,
            "round {round}: byte budget breached by {}",
            state.bytes()
        );
    }
}
