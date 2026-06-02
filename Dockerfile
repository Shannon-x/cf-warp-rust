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
#
# 安全模型：
#   · 容器内 server.bind / metrics.bind 一律由挂载进来的 config.toml 决定，
#     推荐写 0.0.0.0:1080 / 0.0.0.0:9090 —— 容器命名空间内的 0.0.0.0 不等于
#     宿主公网，对外暴露范围完全由宿主侧 `docker run -p` 限定。
#   · 默认 scripts/run-docker.sh 用 `-p 127.0.0.1:1080:1080` 仅绑 loopback；
#     传 --expose 才会改成 `-p 0.0.0.0:1080:1080` 并强制启用 [server.auth]。
#   · 不设 AUTH 又把 server.bind 改成非 loopback 时会被 Config::validate 拒绝
#     （容器场景下 0.0.0.0 + 无 auth 会 warn 但不阻塞，假设宿主 -p 已限定）。
#
# 故意不在镜像里设 ENV WARP_RUST_SERVER__BIND / METRICS__BIND：
#   figment 的 env 优先级高于 toml，固定 ENV 会反过来把挂载的 config.toml 覆盖掉，
#   导致容器内仍只监听 127.0.0.1，宿主 -p 转发不通（issue: bug #1）。
# 如需临时覆盖，仍可在 `docker run` 时显式传 `-e WARP_RUST_SERVER__BIND=...`。

ENTRYPOINT ["/usr/local/bin/warp-rust", "--config", "/app/config.toml"]
