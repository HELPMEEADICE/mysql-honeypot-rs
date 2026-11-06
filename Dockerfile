# syntax=docker/dockerfile:1

# ---- build ---------------------------------------------------------------
FROM rust:1.90-bookworm AS builder

# rusqlite is built with the `bundled` feature, so the SQLite C amalgamation is
# compiled here; no system libsqlite3 is needed at any stage.
WORKDIR /src

# Cache the dependency build: only manifest files first, then sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs && printf '' > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
COPY tests ./tests
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

ENTRYPOINT ["/usr/local/bin/mysql-honeypot-rs"]
CMD ["--config", "/etc/mysql-honeypot/config.toml"]
