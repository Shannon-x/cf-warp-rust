# warp-rust

一个长期常驻、通过 Cloudflare WARP 出口的个人 SOCKS5 代理，用异步 Rust 编写。一次部署，浏览器/CLI 指到 `127.0.0.1:1080`，对外 TCP + UDP 流量就从 Cloudflare 边缘 IP 出去。

## 功能特性

- **首次启动自动注册** Cloudflare WARP 账号；凭据持久化到 `data/account.json`（权限 0600）。后续重启复用同一身份，不会重复消耗注册配额。
- **SOCKS5 CONNECT 与 UDP ASSOCIATE 同时支持。** UDP 报文走 WireGuard 隧道里的用户态 UDP socket，DNS、QUIC 等场景端到端可用，不是只能跑 TCP。
- **用户态 WireGuard**，基于 [`wireguard-netstack`](https://crates.io/crates/wireguard-netstack)（本仓库在 `vendor/` 下做了 fork，新增 UDP 暴露）。**无需 `wg-quick`、无需 TUN 设备、无需 root**。
- **带自愈的 supervisor**，四级恢复阶梯：重连 → 刷新配置 → 重新注册（带 10 分钟冷却防止 Cloudflare 限流）→ 轮转到 `data/identities/` 中的下一个身份。健康探针每 30 秒通过隧道内拨号一次。
- **SIGTERM/SIGINT 优雅停机**，所有子任务响应 CancellationToken，WireGuard 后台任务正常 abort，无残留。
- **Prometheus 指标** 暴露在 `/metrics` 端点（默认 `127.0.0.1:9090`）：连接数、流量字节、探针成败、隧道重建次数、重注册次数、身份轮转次数、活跃 UDP ASSOCIATE 数。
- **配置热重载** — `config.toml` 改动会被监听并立即解析校验，TOML 语法错或字段错会马上在日志里报告。
- **DoS 防护**（v0.1.1）：内置最大并发上限、握手超时、idle 超时、鉴权失败延迟（防暴破），全部可在 `[limits]` 调
- **开放代理保护**（v0.1.1）：启动前校验，**拒绝**「非 loopback bind + 无 auth」组合启动（需 `WARP_RUST_ALLOW_OPEN_PROXY=1` 才能跳过）
- **DNS 可选隧道隔离**（v0.1.1）：`[dns].mode = "tunnel"` 开启后，Domain ATYP 解析也走 WARP，不再向宿主 DNS 泄漏
- **多架构发布**：每个 release 自动发布 Docker 镜像（linux/amd64 + linux/arm64）与预编译二进制（Linux x86_64-musl / Linux aarch64-musl / Windows x86_64 / macOS Apple Silicon）。

---

## ⚡️ 一行命令安装（Linux + systemd 服务器，最推荐）

不用 git clone、不用装 cargo、不用编译——脚本自动检测 x86_64 / aarch64，从 GitHub Release 下载预编译二进制，装 systemd 服务，开机自启。**默认绑 `127.0.0.1` 不需要密码**。

```bash
# === 本机使用（默认 127.0.0.1:1080，无密码）===
curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh | sudo bash

# === 对外暴露端口（自动生成 24 位强密码并打印）===
curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh \
  | sudo bash -s -- --port 1080 --expose

# === 对外暴露 + 自己指定强密码（≥16 位，含大小写+数字）===
curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh \
  | sudo bash -s -- --port 1080 --expose --user me --pass 'MyVeryStrong16Pass'

# === 更新到最新版（保留配置）===
curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh \
  | sudo bash -s -- --update

# === 卸载（保留配置文件，方便重装；要彻底清理脚本最后会提示）===
curl -fsSL https://raw.githubusercontent.com/Shannon-x/cf-warp-rust/main/install.sh \
  | sudo bash -s -- --uninstall
```

安装后会有：
- 二进制在 `/usr/local/bin/warp-rust`
- 配置在 `/etc/warp-rust/config.toml`（权限 0640，仅 root 与服务用户可读）
- 数据在 `/var/lib/warp-rust/`（含 WARP 凭据，权限 0750）
- systemd 服务 `warp-rust.service`，已 `enable --now`，带完整安全 hardening

常用命令：

```bash
sudo systemctl status warp-rust          # 看状态
sudo systemctl restart warp-rust         # 重启
sudo journalctl -u warp-rust -f          # 跟日志
curl --socks5-hostname 127.0.0.1:1080 https://1.1.1.1/cdn-cgi/trace   # 验证（期望 warp=on）
```

---

## 🛠 仓库内脚本（开发场景）

如果你 `git clone` 了仓库，`scripts/` 下另有三个脚本，按场景挑：

| 脚本 | 用法 | 适合场景 |
| --- | --- | --- |
| **`install.sh`** | 一行 `curl …\| sudo bash` 装 systemd 服务 | **生产 Linux 部署（推荐）** |
| **`quickstart.sh`** | 全交互式，逐步问你端口 / 暴露范围 / 鉴权 | 第一次跑、本机调试 |
| **`run-binary.sh`** | 一行带参数；有 `cargo` 就编译，没有就自动下载 release | 本机 / 服务器前台跑 |
| **`run-docker.sh`** | 一行带参数；自动 `docker pull` 或 build | 想用容器隔离 |

### 30 秒上手：本机自用、**无需密码**

```bash
git clone https://github.com/Shannon-x/cf-warp-rust.git
cd cf-warp-rust

# 二进制方式（前台跑；没装 cargo 会自动从 Release 拉对应平台二进制）
./scripts/run-binary.sh
# → 监听 127.0.0.1:1080，无任何鉴权（loopback only，外人到不了）

# 或容器方式（后台跑，自动重启）
./scripts/run-docker.sh
# → 拉 ghcr.io/shannon-x/cf-warp-rust:latest，映射到 127.0.0.1:1080
```

验证一下流量真的从 Cloudflare 出去：

```bash
curl --socks5-hostname 127.0.0.1:1080 https://1.1.1.1/cdn-cgi/trace
# 关键字段：
#   ip=<Cloudflare 出口 IP>     ← 不是你的真实 IP
#   warp=on                      ← 走了 WARP
#   colo=NRT                     ← 出口数据中心代码
```

### ⚠️ 密码什么时候才需要？

**只有把端口绑到 `0.0.0.0` 让外部能访问时（加 `--expose`），脚本才会强制要求密码。** 默认 `127.0.0.1` 模式下完全不要密码：

| 绑定地址 | 谁能访问 | 鉴权 |
| --- | --- | --- |
| `127.0.0.1`（默认） | 仅本机其它进程 | ❌ **不需要密码** |
| `0.0.0.0`（`--expose`） | 互联网/局域网都能访问 | ✅ **强制强密码** |

设计哲学：默认安全且方便——本地无打扰，对外不裸奔。

### 详细用法：`run-binary.sh`

```bash
# 用法：./scripts/run-binary.sh [PORT] [--expose [--user U] [--pass P]]
# PORT 不传默认 1080

# 最简：默认端口 1080，本机无鉴权
./scripts/run-binary.sh

# 换端口
./scripts/run-binary.sh 8964

# 对外暴露 + 自动生成 24 位强密码（推荐做法）
./scripts/run-binary.sh 1080 --expose
# 输出示例：
#   ✓ 自动生成强密码：a8KZmpQfXn5RvtLs0cYHbW3D
#     请立即妥善保存。
#   ▸ SOCKS5 监听：0.0.0.0:1080
#   ▸ 鉴权：warp / 密码见上方或 ./config.runbin.toml

# 对外暴露 + 自定义强密码（≥16 位、含大写+小写+数字，否则拒绝启动）
./scripts/run-binary.sh 1080 --expose --user shannon --pass 'MyVeryStrong16Pass'
```

### 详细用法：`run-docker.sh`

```bash
# 用法：./scripts/run-docker.sh [PORT] [--expose [--user U] [--pass P]] | --stop

# 启动（默认本机 127.0.0.1:1080）
./scripts/run-docker.sh

# 启动到 8964 端口
./scripts/run-docker.sh 8964

# 对外暴露 + 自动强密码
./scripts/run-docker.sh 1080 --expose

# 对外暴露 + 自定义强密码
./scripts/run-docker.sh 1080 --expose --user me --pass 'MyVeryStrong16Pass'

# 停止
./scripts/run-docker.sh --stop

# 指定镜像版本（默认 :latest）
WARP_RUST_IMAGE=ghcr.io/shannon-x/cf-warp-rust:v0.1.0 ./scripts/run-docker.sh
```

容器以 `--restart unless-stopped` 启动，机器重启会自动拉起；镜像优先 `docker pull`，拉不到（如离线）会自动用本地 Dockerfile 构建作为兜底。

### 详细用法：`quickstart.sh`（完全交互式）

```bash
./scripts/quickstart.sh
```

会依次问你：

1. **运行模式**：1=二进制（cargo build），2=Docker 容器
2. **SOCKS5 端口**：默认 1080
3. **绑定范围**：L=仅本机 `127.0.0.1`（推荐），E=对外 `0.0.0.0`
   - 选 E 时会进入密码流程：输入或留空自动生成
4. 若 `config.toml` 已存在，是否覆盖

最后自动生成配置并启动。

### 三种用法对照

```bash
# 本机自用，最简
./scripts/run-binary.sh

# 本机自用 + Docker
./scripts/run-docker.sh

# 公网对外（自动强密码）
./scripts/run-binary.sh 1080 --expose
./scripts/run-docker.sh 1080 --expose

# 公网对外 + 自带密码
./scripts/run-binary.sh 1080 --expose --user me --pass 'MyVeryStrong16Pass'
./scripts/run-docker.sh 1080 --expose --user me --pass 'MyVeryStrong16Pass'
```

---

## 📦 直接下载预编译二进制（不用 cargo）

去 [GitHub Releases](https://github.com/Shannon-x/cf-warp-rust/releases) 下载对应平台的 tar.gz：

| 平台 | 文件名 |
| --- | --- |
| Linux x86_64（musl，静态链接，适合任何发行版） | `warp-rust-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux aarch64（musl，树莓派/Graviton 等） | `warp-rust-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `warp-rust-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon（M1/M2/M3+） | `warp-rust-vX.Y.Z-aarch64-apple-darwin.tar.gz` |

每个包都附带 `.sha256` 校验文件。解压后内含 `warp-rust` 二进制、`config.toml.example`、`scripts/` 与文档。

```bash
# 例：M1 Mac
curl -sSL -O https://github.com/Shannon-x/cf-warp-rust/releases/latest/download/warp-rust-v0.1.0-aarch64-apple-darwin.tar.gz
tar xzf warp-rust-v0.1.0-aarch64-apple-darwin.tar.gz
cd warp-rust-v0.1.0-aarch64-apple-darwin

# 仍然可以用一键脚本（脚本会检测到二进制已存在，跳过 cargo build）
./scripts/run-binary.sh

# 或直接跑
cp config.toml.example config.toml
./warp-rust --config config.toml
```

---

## 🐳 Docker 镜像

多架构镜像自动发布到 GitHub Container Registry：

```bash
# 拉取最新 latest（main 分支构建）
docker pull ghcr.io/shannon-x/cf-warp-rust:latest

# 或指定版本
docker pull ghcr.io/shannon-x/cf-warp-rust:v0.1.0

# 直接 docker run（参考脚本的等价写法）
docker run -d \
  --name warp-rust \
  --restart unless-stopped \
  -p 127.0.0.1:1080:1080 \
  -p 127.0.0.1:9090:9090 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.toml:/app/config.toml:ro \
  ghcr.io/shannon-x/cf-warp-rust:latest
```

镜像内默认 `bind = 0.0.0.0:1080`，对外是否暴露由宿主 `-p` 决定。强烈建议 `-p 127.0.0.1:1080:1080` 只绑 loopback，外部访问通过 SSH/Tailscale 转发更安全。

---

## 手动编译

```bash
cp config.toml.example config.toml
cargo build --release
./target/release/warp-rust --config config.toml
```

## 配置项

`config.toml.example` 已带详细注释。重点参数：

| 表段 | 字段 | 说明 |
| --- | --- | --- |
| `[server]` | `bind` | SOCKS5 监听地址。默认 `127.0.0.1:1080` |
| `[server.auth]` | `username` / `password` | 可选；整个表段省略则无认证（loopback 推荐） |
| `[warp]` | `license_key` | WARP+ 订阅密钥，可选 |
| `[warp]` | `refresh_interval` | 周期刷新 WireGuard 配置的间隔。默认 24h |
| `[warp]` | `register_cooldown` | 两次重注册之间的最小间隔。默认 10m |
| `[health]` | `interval` / `timeout` | 探针节奏（隧道内拨号 1.1.1.1:443） |
| `[recovery]` | `reconnect_after` 等四档 | 触发每一级恢复动作的连续失败次数阈值 |
| `[metrics]` | `enabled` / `bind` | Prometheus `/metrics` 端点 |
| `[hot_reload]` | `enabled` | 是否监听配置文件变化 |

所有字段都可以用环境变量覆盖：`WARP_RUST_SERVER__BIND=0.0.0.0:1080`、`WARP_RUST_WARP__LICENSE_KEY=...`（`__` 分隔表段与字段名）。

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

### systemd（Linux 长驻）

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

### Docker Compose

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
- **许可证。** 本二进制链接了两个 GPL-3.0 crate（`warp-wireguard-gen` 与本地 fork 的 `wireguard-netstack`），因此最终二进制为 **GPL-3.0-or-later**。详见 `LICENSE` 与 [SECURITY.md](SECURITY.md)。

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

scripts/
├── quickstart.sh            一键交互式启动
├── run-binary.sh            一键二进制启动（参数化）
└── run-docker.sh            一键容器启动（参数化）

.github/workflows/
├── ci.yml                   fmt + clippy + test + release build
├── docker.yml               多架构镜像构建（amd64 + arm64）推 GHCR
└── release.yml              多平台二进制构建 + 发布到 Releases
```

## 许可证

GPL-3.0-or-later，详见 `LICENSE`。

## 安全

详细安全模型（零侵入网络、对宿主路由的影响、强密码策略、漏洞报告渠道）见 [SECURITY.md](SECURITY.md)。
