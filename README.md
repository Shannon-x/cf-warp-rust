# warp-rust

一个长期常驻、通过 Cloudflare WARP 出口的个人 SOCKS5 代理，用异步 Rust 编写。一次部署，浏览器/CLI 指到 `127.0.0.1:1080`，对外 TCP + UDP 流量就从 Cloudflare 边缘 IP 出去。

## 功能特性

- **首次启动自动注册** Cloudflare WARP 账号；凭据持久化到 `data/account.json`（权限 0600）。后续重启复用同一身份，不会重复消耗注册配额。
- **SOCKS5 CONNECT 与 UDP ASSOCIATE 同时支持。** UDP 报文走 WireGuard 隧道里的用户态 UDP socket，DNS、QUIC 等场景端到端可用，不是只能跑 TCP。
- **用户态 WireGuard**，基于 [`wireguard-netstack`](https://crates.io/crates/wireguard-netstack)（本仓库在 `vendor/` 下做了 fork，新增 UDP 暴露）。**无需 `wg-quick`、无需 TUN 设备、无需 root**。
- **带自愈的 supervisor**，四级恢复阶梯：重连 → 刷新配置 → 重新注册（带 10 分钟冷却防止 Cloudflare 限流）→ 轮转到 `data/identities/` 中的下一个身份。健康探针每 30 秒通过隧道内拨号一次。
- **SIGTERM/SIGINT 优雅停机**，所有子任务响应 CancellationToken，WireGuard 后台任务正常 abort，无残留。
- **Prometheus 指标** 暴露在 `/metrics`（默认 `127.0.0.1:9090`）：连接数、流量字节、探针成败、隧道重建次数、重注册次数、身份轮转次数、活跃 UDP ASSOCIATE 数。
- **配置热重载** — `config.toml` 改动会被监听并立即解析校验，TOML 语法错或字段错会马上在日志里报告。需要重启才能生效的字段（监听地址、日志级别等）也会在日志里写明。
- **Docker 部署就绪**，多阶段构建到 distroless 运行时镜像。

## 快速开始

```bash
cp config.toml.example config.toml
cargo build --release
./target/release/warp-rust --config config.toml
```

另开终端：

```bash
curl --socks5-hostname 127.0.0.1:1080 https://1.1.1.1/cdn-cgi/trace
# 期望看到：warp=on （如果设置了 license_key 还会有 warp=plus）
```

UDP 链路验证可用任意支持 SOCKS5 UDP 的客户端；本仓库 `tests/` 目录里有一个小 Python 脚本，通过代理对 1.1.1.1:53 发 DNS 查询。

## 配置项

`config.toml.example` 已带详细注释。重点参数：

| 表段 | 字段 | 说明 |
| --- | --- | --- |
| `[server]` | `bind` | SOCKS5 监听地址。默认 `127.0.0.1:1080` |
| `[server.auth]` | `username` / `password` | 可选；整个表段省略则无认证（仅 loopback 推荐） |
| `[warp]` | `license_key` | WARP+ 订阅密钥，可选 |
| `[warp]` | `refresh_interval` | 周期刷新 WireGuard 配置间隔。默认 24h |
| `[warp]` | `register_cooldown` | 两次重注册之间的最小间隔。默认 10m |
| `[health]` | `interval` / `timeout` | 探针节奏（隧道内拨号 1.1.1.1:443） |
| `[recovery]` | `reconnect_after`、`rebuild_config_after`、`reregister_after`、`rotate_identity_after` | 触发每一级恢复动作的连续失败次数阈值 |
| `[metrics]` | `enabled` / `bind` | Prometheus `/metrics` 端点 |
| `[hot_reload]` | `enabled` | 是否监听配置文件变化 |

所有字段也可以用环境变量提供：`WARP_RUST_SERVER__BIND=0.0.0.0:1080`、`WARP_RUST_WARP__LICENSE_KEY=...`，以此类推（`__` 分隔表段与字段名）。

## 身份池（多账号轮转）

当恢复阶梯到达最高一级时，supervisor 会从 `data/identities/` 取下一个身份替换当前账号。生成身份池：

```bash
mkdir -p data/identities
# 反复注册若干次，每次把生成的 account.json 拷进 identities/
for i in 0 1 2 3; do
  rm -rf data/account.json
  ./target/release/warp-rust --config config.toml &
  sleep 6
  kill %1
  wait %1 2>/dev/null
  cp data/account.json data/identities/$i.json
done
```

轮转采用 round-robin；身份池为空时只是停留在当前身份继续重试。

## 部署

### systemd

```ini
[Unit]
Description=warp-rust SOCKS5 proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/warp-rust --config /etc/warp-rust/config.toml
WorkingDirectory=/var/lib/warp-rust
Restart=always
RestartSec=5
User=warp-rust
StateDirectory=warp-rust
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### Docker

```bash
docker compose up -d
# SOCKS5 暴露在 127.0.0.1:1080，/metrics 在 127.0.0.1:9090，数据持久化到 ./data
```

## 可观测性

```bash
curl -s http://127.0.0.1:9090/metrics | grep ^warp_rust
```

关键指标：`warp_rust_conns_opened_total`、`warp_rust_bytes_up_total`、`warp_rust_probe_failure_total`、`warp_rust_tunnel_rebuild_total`、`warp_rust_reregister_total`、`warp_rust_rotate_identity_total`、`warp_rust_udp_associates_active`。

日志格式为 tracing 结构化输出；想看详细内部状态时设置 `RUST_LOG=info,warp_rust=debug`。

## 已知限制与注意事项

- **仅支持 IPv4。** `wireguard-netstack` 目前不支持 IPv6。SOCKS5 客户端给我们 v6 目标地址时会得到 `HostUnreachable` 回复。
- **`DOMAIN` 类型目标地址走宿主机 DNS。** 这样最快、与 `/etc/resolv.conf` 一致，但解析查询本身不走 WARP。如果宿主机上已经有别的 VPN 客户端劫持了 `cloudflare.com` 等常用域名（macOS 上的 1.1.1.1 客户端就会这样），请用 `curl --resolve` 或者直接传 IP 来验证；这是宿主机环境问题，不是代理本身的 bug。
- **许可证。** 本二进制链接了两个 GPL-3.0 crate（`warp-wireguard-gen` 与本地 fork 的 `wireguard-netstack`），因此最终二进制为 **GPL-3.0-or-later**。详见 `LICENSE`。

## 代码结构

```
src/
├── main.rs                  入口；CLI 解析 + 启动序列
├── config.rs                配置 schema + figment 分层加载
├── config_watch.rs          基于 notify 的配置文件监听（v1 仅校验，不热应用）
├── error.rs                 跨模块统一 Error 类型
├── telemetry.rs             tracing-subscriber 初始化
├── signals.rs               SIGTERM/SIGINT → CancellationToken
├── tunnel.rs                ArcSwap<ManagedTunnel>；提供 dial_tcp / bind_udp
├── proxy/
│   ├── mod.rs
│   ├── tcp.rs               SOCKS5 CONNECT（并分派 UDP ASSOCIATE）
│   └── udp.rs               SOCKS5 UDP 数据转发：拆/装包并走隧道
├── warp/
│   ├── account.rs           注册 / 刷新 / 重注册（带冷却）
│   ├── identity_pool.rs     data/identities/ 的 round-robin 轮转
│   └── persistence.rs       0600 权限的 JSON 原子写
├── health.rs                探针循环 → SupervisorEvent
├── supervisor.rs            中央状态机 + 恢复阶梯
└── metrics.rs               Prometheus exporter + axum /metrics 端点

vendor/
└── wireguard-netstack/      上游 fork：新增 smoltcp UDP socket 暴露（见 Cargo.toml）
```

## 许可证

GPL-3.0-or-later，详见 `LICENSE`。
