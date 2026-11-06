// SPDX-License-Identifier: GPL-3.0-only
//! `mysql-honeypot-rs` binary entry point.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use mysql_honeypot_rs::config::Config;
use mysql_honeypot_rs::server;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
mysql-honeypot-rs — a lightweight MySQL honeypot

USAGE:
    mysql-honeypot-rs [OPTIONS]

OPTIONS:
    -c, --config <PATH>   Path to config.toml (default: ./config.toml)
    -h, --help            Print this help
    -V, --version         Print the version

ENVIRONMENT:
    MYSQL_HONEYPOT_CONFIG Alternative way to point at the configuration file.

The honeypot opens exactly one TCP listener (MySQL protocol) and writes every
event to a local SQLite database. It serves no HTTP, WebSocket or admin port.
";

fn main() -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "-c" | "--config" => match arguments.next() {
                Some(path) => config_path = Some(PathBuf::from(path)),
                None => {
                    eprintln!("error: --config needs a path\n\n{USAGE}");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("error: unknown argument '{other}'\n\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }

    let path = config_path
        .or_else(|| std::env::var_os("MYSQL_HONEYPOT_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return ExitCode::FAILURE;
        }
    };

    init_tracing(&config);
    if !path.exists() {
        tracing::warn!(
            path = %path.display(),
            "configuration file not found, using built-in defaults"
        );
    }
    tracing::debug!(path = %path.display(), config = ?config, "configuration loaded");

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("honeypot")
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("cannot start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(server::run(config)) {
        Ok(()) => {
            tracing::info!("honeypot stopped cleanly, all logs flushed");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(error = %err, "honeypot stopped with an error");
            eprintln!("fatal: {err}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(config: &Config) {
    let filter = EnvFilter::try_new(&config.logging.level).unwrap_or_else(|err| {
        eprintln!(
            "invalid logging.level '{}' ({err}), falling back to 'info'",
            config.logging.level
        );
        EnvFilter::new("info")
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
