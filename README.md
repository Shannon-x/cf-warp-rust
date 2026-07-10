# warp-rust

一个长期常驻、通过 Cloudflare WARP 出口的个人 SOCKS5 代理，用异步 Rust 编写。一次部署，浏览器/CLI 指到 `127.0.0.1:1080`，对外 TCP + UDP 流量就从 Cloudflare 边缘 IP 出去。

## 功能特性

- **首次启动自动注册** Cloudflare WARP 账号；凭据持久化到 `data/account.json`（权限 0600）。后续重启复用同一身份，不会重复消耗注册配额。
- **SOCKS5 CONNECT 与 UDP ASSOCIATE 同时支持。** UDP 报文走 WireGuard 隧道里的用户态 UDP socket，DNS、QUIC 等场景端到端可用，不是只能跑 TCP。
- **用户态 WireGuard**，基于 [`wireguard-netstack`](https://crates.io/crates/wireguard-netstack)（本仓库在 `vendor/` 下做了 fork，新增 UDP 暴露）。**无需 `wg-quick`、无需 TUN 设备、无需 root**。
- **带自愈的 supervisor**，四级恢复阶梯：重连 → 刷新配置 → 重新注册（带 10 分钟冷却防止 Cloudflare 限流）→ 轮转到 `data/identities/` 中的下一个身份。默认每 30 秒并发探测 3 个独立公网目标，2 个成功才判定出口健康。
- **SIGTERM/SIGINT 优雅停机**，所有子任务响应 CancellationToken，WireGuard 后台任务正常 abort，无残留。
- **Prometheus 指标** 暴露在 `/metrics` 端点（默认 `127.0.0.1:9090`）：连接数、流量字节、探针成败、隧道重建次数、重注册次数、身份轮转次数、活跃 UDP ASSOCIATE 数。
- **配置变更检测（解析校验，不热应用）** — `config.toml` 改动会被监听并立即重新解析，TOML 语法错或字段错会马上在日志里报告；**但新配置不会自动应用到运行中的进程**，改完后需 `sudo systemctl restart warp-rust` 才生效。`systemd restart` 不会动 `data/account.json`，正在跑的 WARP 凭据/身份轮转状态都会保留。
- **高并发内存平衡**：默认 MTU 1420、256KiB/方向 smoltcp TCP 窗口、64KiB/方向 SOCKS relay buffer；需要单流极限吞吐时可单独调大。
- **DoS 防护**（v0.1.1）：内置最大并发上限、握手超时、idle 超时、鉴权失败延迟（防暴破），全部可在 `[limits]` 调
- **开放代理保护**（v0.1.1 + v0.3.2 收紧）：启动前校验，**拒绝**「非 loopback bind + 无 auth」组合启动。可通过 `WARP_RUST_ALLOW_OPEN_PROXY=1` 整体跳过校验（高风险）；**容器场景**还可通过 `WARP_RUST_TRUSTED_HOST_NET=1` 仅放行「容器内 0.0.0.0 + 宿主 `-p 127.0.0.1:...` 限定」这一窄场景。仓库 `scripts/run-docker.sh` / `docker-compose.yml` / `scripts/quickstart.sh` 已默认注入；**裸 `docker run -p 1080:1080 ghcr.io/...` 启动失败**（v0.3.2 BREAKING：必须显式 opt-in，杜绝意外把无鉴权 SOCKS5 挂到宿主 INADDR_ANY）。
- **DNS 可选隧道隔离**（v0.1.1）：`[dns].mode = "tunnel"` 开启后，Domain ATYP 解析也走 WARP，不再向宿主 DNS 泄漏
- **多架构发布**：每个 release 自动发布 Docker 镜像（linux/amd64 + linux/arm64）与预编译二进制（Linux x86_64-musl / Linux aarch64-musl / Windows x86_64 / macOS Apple Silicon）。

## v0.4.0 相对 v0.3.3：连接可靠性与高并发改进

v0.4.0 的重点是解决“DNS 已经解析成功，但新连接仍然反复 TCP timeout”类问题。它不改变 SOCKS5 协议或使用方式，主要重做拨号、连接生命周期与健康判定。完整条目见 [v0.4.0 发布说明](https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.4.0)。

| 维度 | v0.3.3 之前 | v0.4.0 改进 |
| --- | --- | --- |
| 域名拨号 | 只保留首个 A/AAAA 地址，其余 DNS 候选不会被尝试 | 缓存完整 A/AAAA 记录集，交错排列并错峰尝试最多 8 个候选。一个 IP 超时时会继续尝试其他候选 |
| 高并发拨号 | 临时端口随机抽取，高并发时可能碰撞；所有 socket 共享唤醒 | 32768 个无冲突端口、TCP/UDP 分离；每 socket 独立事件唤醒，移除 1ms 忙轮询与全局惊群 |
| 稳态内存 | 默认单连接缓冲约 2.5 MiB（2 x 1 MiB TCP + 2 x 256 KiB relay） | 默认约 640 KiB（2 x 256 KiB TCP + 2 x 64 KiB relay），更适合高并发场景 |
| 长连接 / idle | 上下行单独计时，单向持续下载或上传也可能被误杀 | 任一方向成功传输都会续期，只有双向无进展才超时；UDP 也使用真正的活动 idle |
| 隧道热替换 | 替换旧隧道可以中止仍存活连接的后台驱动 | TCP/UDP 句柄持有旧隧道租约；新连接走新隧道，旧连接可自然结束 |
| 自愈与就绪性 | 单一 1.1.1.1 探针，第一级恢复就会访问 API | 3 个公网目标的 2/3 quorum；第一级只复用已验证配置重连，更高阶段才请求 API |
| 取消与账号安全 | 某些取消路径会 detach 子任务；身份切换先覆盖本地账号 | relay 子任务 abort-on-drop 并回收；候选身份先完成握手，再原子持久化与切换 |
| 网络与协议防护 | 隧道 DNS 校验较少，UDP ASSOCIATE 的客户端源地址约束不足 | DNS 随机事务 ID 及回包来源/flags/rcode 校验；UDP 绑定 TCP peer IP 与首个源端口；密码使用常量时间比较 |
| 运维可观测性 | 只能以端口连通判断健康 | `/healthz` 反映公网出口 quorum，`/livez` 只判断进程存活；增加拨号尝试/失败/超时指标 |

### 从 v0.3.3 升级时的注意事项

- 旧 `config.toml` 如果显式写了 `tcp_buffer_size = 1048576` 或 `relay_buffer_size = 262144`，升级不会自动改掉这些值。想使用 v0.4.0 的默认内存模型，请改为 262144 和 65536。
- 为了让域名多候选拨号生效，建议在 `[limits]` 显式配置 `connect_timeout = "12s"`、`happy_eyeballs_delay = "200ms"`、`max_dial_candidates = 8` 和 `max_parallel_dials = 2`。
- systemd 部署请用 `/healthz` 做 readiness 探测，用 `/livez` 做进程存活检查。

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
  -e WARP_RUST_TRUSTED_HOST_NET=1 \
  ghcr.io/shannon-x/cf-warp-rust:latest
```

> 提示：v0.3.2 起若 `config.toml` 里 `[server].bind = 0.0.0.0:...` 且无 `[server.auth]`，必须显式 `-e WARP_RUST_TRUSTED_HOST_NET=1` 才能启动（声明宿主已用 `-p` 限定 loopback）。仓库脚本会自动注入；裸 `docker run` 需要自己加。或者改用 `[server.auth]` username/password 方式，则不再需要 trust env。
>
> 提示：如果 `./config.toml` 不存在又传了 `-v $(pwd)/config.toml:/app/config.toml:ro`，docker 会把它当空目录挂入，容器启动会失败。先 `cp config.toml.docker.example config.toml`，或者干脆不传那行 `-v config.toml` 让容器用镜像内置默认。

镜像内默认 `bind = 0.0.0.0:1080`（来自 `config.toml.docker.example`，是**容器命名空间内**的 0.0.0.0，不等于宿主公网）。对外是否暴露完全由宿主 `docker run -p` 决定：

- `-p 127.0.0.1:1080:1080`（**推荐的默认安全姿势**）→ 仅本机可访问，外部用 SSH/Tailscale 转发；
- `-p 0.0.0.0:1080:1080` 或 `-p 1080:1080` → 暴露到所有网卡。此时**强烈建议**在 `config.toml` 配 `[server.auth]`（≥16 位强密码）。

v0.3.2 起新增 `WARP_RUST_TRUSTED_HOST_NET=1`：声明「宿主已用 `-p 127.0.0.1` 限定，我对宿主网络负责」。容器内 `0.0.0.0` + 无 `[server.auth]` 时**必须**设此 env 才能启动，否则被 `Config::validate` 拒绝（启动失败、stderr 明示）。仓库自带的 `scripts/run-docker.sh`、`docker-compose.yml`、`scripts/quickstart.sh` 已自动注入。

如果想自定义配置：`cp config.toml.docker.example config.toml`（**不要**用 `config.toml.example`，那份是给宿主直跑的，默认 `127.0.0.1` 在容器内拿不到 `-p` 转发，正是 bug3 根因），改完再 `docker run -e WARP_RUST_TRUSTED_HOST_NET=1 -v $(pwd)/config.toml:/app/config.toml:ro ...`。

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
| `[warp]` | `mtu` | WireGuard MTU。默认 1420；PMTU 不稳时可回退 1280 |
| `[warp]` | `tcp_buffer_size` | smoltcp TCP 单向窗口。默认 262144；每连接约占 2 倍内存 |
| `[limits]` | `relay_buffer_size` | SOCKS TCP 每方向 relay buffer。默认 65536 |
| `[limits]` | `relay_close_grace` | v0.3.2：双向 relay 中一侧退出后给对端的优雅窗口；超时 abort 兜底。默认 `500ms` |
| `[limits]` | `connect_timeout` / `happy_eyeballs_delay` | 全候选总超时与错峰拨号间隔 |
| `[limits]` | `max_dial_candidates` / `max_parallel_dials` | 每个目标的候选数和同时在飞拨号硬上限 |
| `[health]` | `interval` / `timeout` / `targets` / `min_successes` | 多目标 quorum 公网出口探针 |
| `[dns]` | `mode` / `max_cache_entries` | 宿主/隧道 DNS 选择与有界缓存 |
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

### 查看日志

`install.sh` 安装后服务跑在 systemd 下，日志走 **systemd-journald**（不是文件），用 `journalctl` 看：

```bash
# 实时跟随（推荐排错用，Ctrl-C 退出）
sudo journalctl -u warp-rust -f

# 最近 100 行
sudo journalctl -u warp-rust -n 100

# 看某个时间窗口
sudo journalctl -u warp-rust --since '1 hour ago'
sudo journalctl -u warp-rust --since today
sudo journalctl -u warp-rust --since '2026-06-01 06:00' --until '2026-06-01 07:00'

# 只看错误及以上级别
sudo journalctl -u warp-rust -p err

# 看 boot 以来的日志
sudo journalctl -u warp-rust -b

# 持续占用磁盘多少
sudo journalctl --disk-usage
```

**手动跑二进制时**（开发场景，不用 systemd），日志直接打到 stdout/stderr，用 `tee` 落盘：

```bash
RUST_LOG=info,warp_rust=info ./target/release/warp-rust --config config.toml 2>&1 | tee warp-rust.log
```

### 日志级别 / 格式

`config.toml` 的 `[logging]` 段：

```toml
[logging]
# tracing env-filter 表达式；RUST_LOG 环境变量优先于此
level = "warn,warp_rust=info"
# 输出格式：compact（默认精简）/ pretty（开发友好彩色）/ json（机器友好）
format = "compact"
```

**install.sh 安装的服务**默认是 `warn,warp_rust=info`——第三方依赖只 warn 以上，自己模块 info，正常运行几乎不写日志，每天通常 <100 KB。要更详细：

```bash
sudo sed -i 's|^level = .*|level = "info,warp_rust=debug,wireguard_netstack=info"|' /etc/warp-rust/config.toml
sudo systemctl restart warp-rust
sudo journalctl -u warp-rust -f
```

**JSON 格式**（导入 Loki/ELK）：

```toml
[logging]
level = "info,warp_rust=info"
format = "json"
```

### Prometheus 指标

```bash
curl -s http://127.0.0.1:9090/metrics | grep ^warp_rust
# readiness：多目标出口 quorum 通过才返回 200；livez 只检查进程存活
curl -f http://127.0.0.1:9090/healthz
curl -f http://127.0.0.1:9090/livez
```

关键指标：

| 指标 | 类型 | 含义 |
| --- | --- | --- |
| `warp_rust_conns_opened_total` / `conns_closed_total` | counter | SOCKS5 TCP 累计开/关数 |
| `warp_rust_conns_rejected_total` | counter | 因并发上限被拒数 |
| `warp_rust_bytes_up_total` / `bytes_down_total` | counter | 上下行累计字节 |
| `warp_rust_probe_success_total` / `probe_failure_total` | counter | 健康探针成败数 |
| `warp_rust_dial_attempt_total` / `dial_failure_total` / `dial_timeout_total` | counter | 多候选拨号尝试、失败与整体超时 |
| `warp_rust_tunnel_rebuild_total` | counter | 隧道重建数（自愈触发） |
| `warp_rust_reregister_total` | counter | WARP 重注册数 |
| `warp_rust_rotate_identity_total` | counter | 身份池轮转数 |
| `warp_rust_udp_associates_active` | gauge | 当前活跃 UDP ASSOCIATE |
| `warp_rust_netstack_sockets_active` | gauge | 当前 netstack 内 socket 数（TCP+UDP）。**内存健康核心指标**：稳态应贴合活跃连接数；若活跃连接平稳而此值单调上升，即为 socket 泄漏（v0.3.3 已修） |
| `warp_rust_dns_query_total` / `dns_cache_hit_total` | counter | DNS 查询 / 缓存命中 |
| `warp_rust_wg_tx_backpressure_total` | counter | WG 出口通道满时触发回压重试次数 |
| `warp_rust_wg_tx_dropped_total` | counter | WG 出口通道关闭时丢弃的包（异常预警） |
| `warp_rust_netstack_rx_queue_dropped_total` | counter | netstack 有界 RX 队列满时丢包（持续增长表示 CPU/带宽过载） |
| `warp_rust_handshake_timeout_total` / `idle_timeout_total` / `auth_fail_total` | counter | DoS 防护各类拦截 |

进程 RSS / CPU / 文件描述符不由本程序伪造导出；Linux 部署可另外采集 `node_exporter` 或 `process-exporter`，也可把 systemd/cgroup 指标与上述业务指标联图。

### 内存 / CPU 速查

> 内存泄漏自查（v0.3.3+）：抓 `warp_rust_netstack_sockets_active`，它应稳定贴合活跃连接数。
> 若它随时间单调上升而并发连接数平稳，说明有 socket 未释放——v0.3.3 已修复 `TcpConnection::connect`
> 在失败/取消路径上泄漏 `2×tcp_buffer_size` 的 socket buffer，升级即可。每条 TCP 连接稳态占用约
> `2×tcp_buffer_size`（默认 256KiB → 512KiB），另加两方向 relay buffer（默认共 128KiB）。

```bash
# systemctl 自带（最简单）
sudo systemctl status warp-rust   # 直接显示 Memory + CPU

# 即时一行
ps -o pid,user,%cpu,%mem,rss,etime -p $(pgrep warp-rust)

# 30s 间隔持续观察（含 RSS 历史峰值）
while :; do
  PID=$(pgrep warp-rust) && printf '%s  RSS=%6sKB  HWM=%6sKB  CPU=%s%%\n' \
    "$(date +%H:%M:%S)" \
    "$(awk '/^VmRSS/{print $2}' /proc/$PID/status)" \
    "$(awk '/^VmHWM/{print $2}' /proc/$PID/status)" \
    "$(ps -p $PID -o %cpu= | tr -d ' ')"
  sleep 30
done
```

### 几个常用排查命令

```bash
# 服务整体状态（含最近 10 行日志）
sudo systemctl status warp-rust

# 看上次启动失败原因
sudo journalctl -u warp-rust --since '5 min ago' -p warning

# 验证流量真的走 WARP
curl --socks5-hostname 127.0.0.1:1080 https://1.1.1.1/cdn-cgi/trace | grep -E '^(ip|warp|colo)='

# 看 SOCKS5 端口监听状态
ss -tlnp | grep warp-rust
```

## 已知限制与注意事项

- **支持 IPv4 与 IPv6 出口（v0.2.0+）。** WARP 给的 `addresses.v6` 会被解析并配置到 netstack；SOCKS5 客户端给 IPv6 目标地址、或 SOCKS5 UDP ATYP=0x04，都能通过 WARP IPv6 出口访问。Domain ATYP 会保留完整 A/AAAA 集合并按 Happy Eyeballs 错峰尝试。
- **`DOMAIN` 类型目标地址走宿主机 DNS。** 这样最快、与 `/etc/resolv.conf` 一致，但解析查询本身不走 WARP。如果宿主机上已经有别的 VPN 客户端劫持了 `cloudflare.com` 等常用域名（macOS 上的 1.1.1.1 客户端就会这样），请用 `curl --resolve` 或者直接传 IP 来验证；这是宿主机环境问题，不是代理本身的 bug。开启 `[dns].mode = "tunnel"` 后域名走隧道内 1.1.1.1:53。
- **SOCKS5 BIND 不支持**，**UDP 分片不支持**：协议层留作后续版本增强。
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
