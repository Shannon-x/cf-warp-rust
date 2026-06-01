# syntax=docker/dockerfile:1.6
#
# 多阶段构建：在 debian-slim 上用 cargo 构建，运行时切到 distroless
# 运行层有 glibc 但无 shell，攻击面小

# ── builder ──────────────────────────────────────────────────────────────────
FROM rust:1.95-slim-bookworm AS builder
WORKDIR /src

# 只在构建时需要的系统依赖；运行时使用 rustls，无需 openssl-dev
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 依赖层缓存：先复制 manifest 与 vendor，再复制源码
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --bin warp-rust && \
    rm -rf src

COPY src ./src
# touch 一下让 cargo 用真源码重建（前一步只构建了 stub）
RUN touch src/main.rs && cargo build --release --bin warp-rust

# ── runtime ──────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /src/target/release/warp-rust /usr/local/bin/warp-rust
COPY config.toml.example /app/config.toml

# data/ 用于持久化身份与凭据
VOLUME ["/app/data"]

EXPOSE 1080 9090

# 1080 = SOCKS5；9090 = Prometheus /metrics
# 容器内监听 0.0.0.0；宿主机映射端口随意
ENV WARP_RUST_SERVER__BIND=0.0.0.0:1080 \
    WARP_RUST_METRICS__BIND=0.0.0.0:9090

ENTRYPOINT ["/usr/local/bin/warp-rust", "--config", "/app/config.toml"]
