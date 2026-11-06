# `cargo-fuzz` harnesses for `mysql-honeypot-rs`

Four `libFuzzer` targets covering the crate's **stable parsing surface**: the
bounds checked payload reader, the 4.1 handshake response parser, the TOML
config loader and the MySQL packet framer.

This directory is its own cargo workspace. It is deliberately **not** a member
of the parent workspace, so `cargo build`, `cargo test`,
`cargo fmt --all -- --check` and `cargo clippy --all-targets` at the repository
root never build any of it.

## Requirements

* A **nightly** toolchain. `cargo-fuzz` builds with `-Z sanitizer=address`,
  which does not exist on stable:

  ```sh
  rustup toolchain install nightly
  ```

* `cargo-fuzz` itself:

  ```sh
  cargo install cargo-fuzz
  ```

## Running a target

From the repository root:

```sh
cargo +nightly fuzz run packet    -- -max_total_time=60
cargo +nightly fuzz run handshake -- -max_total_time=60
cargo +nightly fuzz run config    -- -max_total_time=60
cargo +nightly fuzz run framing   -- -max_total_time=60
```

`-max_total_time=60` bounds a run to 60 seconds; leave it out to fuzz until you
interrupt, or add `-rss_limit_mb=2048` on a small machine.

Seed corpora land in `fuzz/corpus/<target>/` and crashes in
`fuzz/artifacts/<target>/`; both are git ignored. Reproduce a finding with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

`cargo +nightly fuzz list` must print exactly the four targets above, matching
the `[[bin]]` entries in `Cargo.toml`.

## What these harnesses never do

The targets feed **bytes only** into pure parsing functions. They never execute
SQL (no statement is parsed, prepared or run), never touch the filesystem (no
file is opened and no SQLite database is reached) and never open a socket (the
framing target uses `tokio::io::duplex`, an in-memory pipe, and enables no I/O
driver on its runtime).

Everything is safe code, and nothing here depends on `fakedb`: the query
dispatcher is not part of the parsing surface being fuzzed.

## What each target asserts

| Target | Surface | Invariant |
| --- | --- | --- |
| `packet` | `protocol::packet::PayloadReader`, `util::truncate_to` | no accessor panics; the cursor never moves backwards or past the payload; `remaining() == data.len() - position()`; `rest()` consumes the reader exactly once and returns a suffix; truncation never splits a UTF-8 character and never exceeds its byte cap |
| `handshake` | `protocol::handshake::parse_handshake_response`, `is_ssl_request` | `is_ssl_request` answers for every length and mirrors the `CLIENT_SSL` bit; on `Ok` the capability word, `max_packet_size` and `charset` round-trip verbatim, `attrs.len() <= 32`, and no field is longer than the payload it came from |
| `config` | `config::Config::from_toml` | hostile TOML never panics; a parsed config is already clamped — `1 <= server.max_connections <= 65_535`, `max_packet_size` within `4096..=64 MiB`, `delay_min_ms >= 1`, `delay_min_ms <= delay_max_ms`, and every other `sanitize()` range holds |
| `framing` | `protocol::packet::PacketStream::read_packet` | every read terminates and returns a `Result`; an accepted payload never exceeds the 1 MiB cap; at most 4 reads per iteration, and the writer task is aborted rather than awaited |

## Adding a target

Create `fuzz_targets/<name>.rs` with `#![no_main]` and a `fuzz_target!` body,
then add the matching `[[bin]]` entry (`path = "fuzz_targets/<name>.rs"`,
`test = false`, `doc = false`, `bench = false`) to `Cargo.toml`. Keep the
manifest and the directory in lockstep: `cargo fuzz list` must show exactly the
files that exist.
