# syntax=docker/dockerfile:1

# ---- build ---------------------------------------------------------------
# `Cargo.toml` declares `edition = "2024"`, which needs Rust 1.85 or newer; the
# builder is pinned to a concrete minor version so the build stays reproducible.
FROM rust:1.90-bookworm AS builder

# rusqlite is built with the `bundled` feature, so the SQLite C amalgamation is
# compiled here; no system libsqlite3 is needed at any stage.
WORKDIR /src

# Cache the dependency build: only manifest files first, then sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs && printf '' > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

# `cargo build` compiles `src/lib.rs` and `src/main.rs` only; the integration
# tests under `tests/` are not part of a release build and stay out of the image.
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# ---- runtime -------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Unprivileged account, no shell, home points at the only writable directory.
RUN groupadd --system --gid 10001 honeypot \
    && useradd --system --uid 10001 --gid honeypot --home-dir /data \
       --shell /usr/sbin/nologin honeypot \
    && mkdir -p /data /etc/mysql-honeypot \
    && chown -R honeypot:honeypot /data

COPY --from=builder /src/target/release/mysql-honeypot-rs /usr/local/bin/mysql-honeypot-rs
COPY deploy/config.docker.toml /etc/mysql-honeypot/config.toml

USER 10001:10001
WORKDIR /data

# The SQLite log database lives here; mount a volume to keep it.
VOLUME ["/data"]

# The honeypot's only listening socket.
EXPOSE 3306

# No HEALTHCHECK, deliberately. The process speaks the MySQL protocol and
# nothing else, and this image ships no client that can speak it: /bin/sh is
# dash, which has no /dev/tcp, and there is no mysql/mariadb client or netcat.
# A container-level probe would therefore either fail permanently or need extra
# packages, so liveness is left to an operator-side TCP check on port 3306.
ENTRYPOINT ["/usr/local/bin/mysql-honeypot-rs"]
CMD ["--config", "/etc/mysql-honeypot/config.toml"]
