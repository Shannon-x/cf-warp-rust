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
# 注意：这里复制的是 **docker 专用** example（bind = 0.0.0.0:1080 / 0.0.0.0:9090），
# 不是 config.toml.example。config.toml.example 默认 127.0.0.1 是给宿主直跑用的，
# 在容器命名空间内绑 loopback 会让宿主 `-p` 转不通（issue: bug3）。
# 容器命名空间里的 0.0.0.0 不等于宿主公网，对外暴露范围完全由宿主 `docker run -p`
# 决定；推荐挂载用户自己改过的 config（从 `config.toml.docker.example` 拷贝而来）。
# 详见 README『Docker 镜像』一节。
COPY config.toml.docker.example /app/config.toml

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
#   · 不设 AUTH 又把 server.bind 改成非 loopback 时会被 Config::validate 拒绝。
#
# v0.3.2 BREAKING（issue: bug4）：容器内 0.0.0.0 + 无 [server.auth] 时**额外**
# 要求 `-e WARP_RUST_TRUSTED_HOST_NET=1` 才能启动 —— 语义即「部署方已用宿主
# -p 127.0.0.1 限定，对宿主网络栈安全负责」。
#   · 镜像故意**不设**这个 ENV 默认值：若设了默认值，裸 `docker run -p 1080:1080
#     ghcr.io/...` 仍然能启动并把无鉴权 SOCKS5 挂到宿主 INADDR_ANY，等同于
#     v0.3.1 的开放代理姿势，本次修复就白做了。
#   · 走仓库 scripts/run-docker.sh / docker-compose.yml / scripts/quickstart.sh
#     的用户无感（这三个调用方都显式注入 -e WARP_RUST_TRUSTED_HOST_NET=1）。
#   · 手搓 `docker run` 的用户必须自己选：
#       a) 加 -e WARP_RUST_TRUSTED_HOST_NET=1（前提：你确实用 -p 127.0.0.1: 限定），或
#       b) 在 config.toml 配 [server.auth]，或
#       c) -e WARP_RUST_ALLOW_OPEN_PROXY=1（整体绕过，含弱密码等其它校验，不推荐）
#
# 故意不在镜像里设 ENV WARP_RUST_SERVER__BIND / METRICS__BIND：
#   figment 的 env 优先级高于 toml，固定 ENV 会反过来把挂载的 config.toml 覆盖掉，
#   导致容器内仍只监听 127.0.0.1，宿主 -p 转发不通（issue: bug #1）。
# 如需临时覆盖，仍可在 `docker run` 时显式传 `-e WARP_RUST_SERVER__BIND=...`。

ENTRYPOINT ["/usr/local/bin/warp-rust", "--config", "/app/config.toml"]
