// SPDX-License-Identifier: GPL-3.0-only
//! `mysql-honeypot-rs` — a lightweight MySQL honeypot.
//!
//! The crate speaks enough of the MySQL wire protocol (protocol version 10,
//! 4.1+) to make automation believe it reached a real MySQL server, accepts any
//! credentials, stalls each login by a random amount of time and records every
//! statement an attacker submits into a local SQLite database.
//!
//! Nothing in this crate ever executes attacker supplied SQL, touches the host
//! filesystem on behalf of a client, or opens outbound connections.

// A honeypot parses hostile input all day; it may not contain a single unsafe
// block for that parsing to be able to undermine.
#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod fakedb;
pub mod protocol;
pub mod server;
pub mod sqlite_log;
pub mod util;

pub use config::Config;
pub use server::run;
