# 安全说明

本文档解释 `warp-rust` 在系统上的影响范围、默认安全姿态，以及对外暴露时的硬性要求。

## 1. 对宿主系统的网络影响：**零侵入**

`warp-rust` 使用 **用户态 WireGuard**（`gotatun` / `boringtun` 思路）+ **用户态 TCP/IP 栈**（`smoltcp`）。整个隧道完全跑在进程内部，对宿主操作系统的影响只有：

| 行为 | 是否发生 |
| --- | --- |
| 创建 TUN / TAP 设备 | ❌ 不会 |
| 修改路由表（`route` / `ip route` / `netsh`） | ❌ 不会 |
| 修改 iptables / nftables / pfctl / 防火墙 | ❌ 不会 |
| 改写 `/etc/resolv.conf` 或 DNS 设置 | ❌ 不会 |
| 申请 `CAP_NET_ADMIN` / root 权限 | ❌ 不需要 |
| 占用宿主 socket | ✅ 仅 1 个出站 UDP 到 162.159.x:2408；1 个 SOCKS5 监听端口；1 个 metrics 监听端口 |
| 写入文件 | ✅ 仅在 `data_dir`（默认 `./data/`）写凭据 JSON（权限 0600） |

**进程被 kill 之后系统就完全恢复原样**——重启系统也不会发现任何痕迹。

如果你担心，可以观察：
```bash
# 启动前
ss -tunap | wc -l         # 或 netstat -an | wc -l
ip rule show              # Linux
netstat -nr               # macOS / *BSD

# 启动 warp-rust 之后再跑一遍，对比 —— 只会多出一个出站 UDP 和两个监听端口
```

## 2. 默认本地访问

`config.toml.example` 与所有脚本默认都把 SOCKS5 绑在 `127.0.0.1`：

```toml
[server]
bind = "127.0.0.1:1080"
```

**只有本机进程能用**。任何其他机器、容器、Wi-Fi 邻居都无法到达。这是默认推荐姿态。

## 3. 对外暴露：**强制强密码鉴权**

如果你确实要把代理对外提供（脚本里 `--expose`，或手动改 `bind = "0.0.0.0:..."`），脚本会**强制**启用 SOCKS5 用户名/密码鉴权，且密码必须满足：

- 长度 ≥ 16
- 至少含一个 **大写字母**
- 至少含一个 **小写字母**
- 至少含一个 **数字**

不传 `--pass` 时脚本会用 `/dev/urandom` 自动生成 **24 位字母数字混合密码**（约 143 bits 熵），并打印到终端供你保存。手动传弱密码会被直接拒绝。

```bash
# 自动生成（推荐）
./scripts/run-binary.sh 1080 --expose
# ✓ 自动生成强密码：a8KZmpQfXn5RvtLs0cYHbW3D

# 自己指定，必须强
./scripts/run-binary.sh 1080 --expose --user shannon --pass 'MyVeryStrong16P@ss'
```

⚠️ 即便如此，把代理直接暴露公网仍然不是最佳实践：
- 优先考虑 **WireGuard / Tailscale 把客户端拉进同一私网**，再连本地 127.0.0.1:1080
- 或者用 nginx / Caddy 在前面做 TLS 终止 + 速率限制 + IP 白名单
- 容器场景下尽量只把端口 `-p 127.0.0.1:1080:1080` 绑到 loopback，再通过反代/ssh tunnel 出去

## 3.1 v0.1.1 新增的运行时强约束

- **启动前校验 `Config::validate()`**：`server.bind` 是非 loopback（含 `0.0.0.0`）且 `[server.auth]` 为空时**直接拒绝启动**，错误信息会同时打到 stderr 和 systemd journal。要绕过必须 `export WARP_RUST_ALLOW_OPEN_PROXY=1`（高风险，会有 WARN 日志）。
- **`[limits]` DoS 防护**（默认值，可调）：
  - `max_concurrent_connections = 1024`：满则新连接立即关闭，记 `warp_rust_conns_rejected_total`
  - `handshake_timeout = 10s`：SOCKS5 握手+`read_command` 总超时，超时即关
  - `idle_timeout = 300s`：双向 relay 无数据传输到达即关
  - `auth_fail_sleep = 1s`：每次鉴权失败强制延迟，缓解暴破
- **`[dns]` 域名解析隔离**（默认 `mode = "system"`）：
  - `mode = "tunnel"` 时 Domain ATYP 走隧道内 UDP 拨 `[1.1.1.1:53, 1.0.0.1:53]`
  - 带 60s LRU 缓存，命中无额外 RTT
  - 对极度隐私敏感的场景必开
- **TCP socket 资源泄漏修复**：v0.1.0 在 SOCKS5 / 健康探针每次连接关闭时会把 smoltcp socket（128 KB buffer）留在 SocketSet 永不释放。v0.1.1 起 Drop 强制 `remove_socket`，**RSS 长期稳定**。

## 4. 凭据与密钥保护

- `data/account.json`（含 WARP private_key 和 access_token）始终写成 **0600**（仅当前用户可读写）
- `config*.toml` 由脚本生成时也是 0600
- `.gitignore` 已经把 `data/` 和顶层 `config.toml` 排除，不会被 `git add -A` 误提交
- Docker 部署时 `data/` 通过 volume 挂载，**不要**把它打进镜像

## 5. WARP 注册接口的滥用保护

Cloudflare 对注册接口有源 IP 限流。`warp-rust` 的 supervisor 内置：

- **10 分钟最小冷却**：两次重注册之间强制等待，由 `[warp].register_cooldown` 控制
- **恢复阶梯前的指数退避**：500ms → 30s
- **身份池空时不重试**：避免在死循环里耗光所有备用账号

## 6. 已知限制

- **仅 IPv4**：netstack 不支持 IPv6 目标
- **Domain ATYP 走宿主 DNS**：解析查询本身不走 WARP（性能/兼容性优先）。需要纯净出口的，可以用 `--resolve` 或直接传 IP
- **TLS 终止**：本程序不做 TLS。SOCKS5 自身没有传输加密，对外暴露务必走 WireGuard/Tailscale/SSH 等加密通道

## 7. 漏洞报告

发现安全问题请发邮件给 `shannon8804@gmail.com`（GPG 公钥已在 GitHub 个人页面），或在 GitHub 上开 **Private vulnerability report**（不要直接开 public issue）。
