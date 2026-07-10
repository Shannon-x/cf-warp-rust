# 更新日志

本项目的所有重要变更记录于此。版本遵循语义化版本（SemVer）。
日期格式为 `YYYY-MM-DD`。

## [0.4.1] - 2026-07-10

### 修复

- 修复重复运行安装向导时仅执行 `systemctl enable --now`、不会重启已经 active 的旧进程的问题。现在安装/重装会备份旧配置、明确 restart/start、打印运行中进程版本，失败不再被 `|| true` 吞掉，并只读取本次启动后的 journal。
- 修复“磁盘已安装 v0.4.x、内存仍运行 v0.3.x、配置却已覆盖为新版”导致的版本/行为混杂；readiness 不再依赖日志窗口恰好出现 `SOCKS5 listening`。
- 修复 WARP 默认 UDP 端点不可达时恢复状态机不断重试同一端口的问题；现在按 API 端口优先，并有界回退 UDP 2408/500/1701/4500，成功端口会写回后续 reconnect 状态。
- 升级间接依赖 `anyhow 1.0.102 → 1.0.103`，消除 `RUSTSEC-2026-0190` 的 `downcast_mut` unsoundness。

### 优化 / 加固

- supervisor 判定隧道不健康后，SOCKS5 TCP/UDP 请求快速返回标准失败，不再为客户端重试风暴持续分配 netstack socket。
- 新增 `[limits].max_pending_dials`（默认 128），把建连阶段与已建立连接分别限流，将坏线路下 Happy Eyeballs 最坏 buffer 峰值限制在固定范围。
- 上游拨号失败日志改为 debug 明细 + 每 2 秒一条聚合 warning；连接失败指标仍逐次精确累计，避免 journald 洪水反过来消耗 CPU/磁盘。
- 新增 `warp_rust_conns_rejected_tunnel_unhealthy_total` 与 `warp_rust_conns_rejected_dial_pressure_total`，可区分隧道故障和建连压力拒绝。
- 新增安装升级、端点回退和建连容量校验回归测试。

## [0.4.0] - 2026-07-10

### 修复

- DNS 现在保留并缓存完整 A/AAAA 记录集；有界 Happy Eyeballs 会错峰尝试全部候选，不再只试首个 v4/v6 地址。
- 修复 smoltcp 临时端口随机碰撞、connect 取消后的端口回收、poll_at 时钟域不一致。
- 用每 socket 的 connect/read/write/UDP 通知替代 1ms 忙轮询和全局惊群通知。
- 多目标多数派出口探针取代单一 1.1.1.1 探针，并丢弃恢复期间排队的过期探针事件。
- 恢复阶梯第一级现在复用内存中已验证配置直接重连；只有更高一级才访问 Cloudflare API。
- TCP/UDP 句柄现在持有创建它的隧道租约，热替换不再中止旧连接的后台驱动任务。
- TCP idle timeout 改为上下行共享活动计时，持续的单向下载/上传不再被误杀。
- 修复 UDP ASSOCIATE 源地址劫持、把会话寿命误当 idle timeout、子任务退出后 relay 残留，以及超时 JoinHandle detach。
- 修复关键服务退出后主进程仍假装健康、WARP API/DNS 请求无总超时、身份轮换/重注册在新隧道握手前覆盖现用账号。
- 隧道 DNS 校验随机 transaction ID、响应源/flags/rcode，并拒绝截断或畸形域名。

### 优化 / 加固

- 默认 TCP 单向 buffer 从 1MiB 调整为 256KiB，relay 每方向从 256KiB 调整为 64KiB。
- DNS 缓存、虚拟设备包队列、拨号候选和候选并发均增加硬上限；缓存满载淘汰为 O(1)。
- 临时端口扩到 32768 个并与配置容量联动校验，高并发 Happy Eyeballs 不会过量承诺。
- WARP API bearer token 不再走可 panic 的 HeaderValue unwrap；SOCKS 密码改为常量时间比较。
- 公网监听强制 16 位、含大小写和数字的密码；`/healthz` 反映真实出口 quorum，`/livez` 保留进程存活检查。
- 未使用的 wireguard-netstack DoH/config 模块改为 feature gate，减少生产二进制攻击面。

## [0.3.3] - 2026-06-29

### 修复（内存泄漏，重点）

- **`TcpConnection::connect` 在「连接成功之前」的失败/取消路径上泄漏 socket buffer。**
  `create_tcp_socket()` 会立即把携带 `rx + tx = 2×tcp_buffer_size`（默认 1MiB → **2MiB**）的
  smoltcp socket 加入 `SocketSet`，而唯一兜底释放的 `Drop for TcpConnection` 只在 `Ok(Self)`
  构造成功后才存在。于是以下三条路径每次都会把 2MiB 永久遗留在主隧道的 `SocketSet` 里，
  跨连接单调累积（现场实测 RSS 涨到 ~1.6 GiB、AnonHugePages ~1.3 GiB 与 THP 2MiB 粒度对齐）：
  - **路径 A**：`netstack.connect()?` 提前返回 `Err`（无 v6 隧道时的 `Ipv6NotSupported` 等）；
  - **路径 B**：happy-eyeballs 双栈拨号时，`tokio::select!` 的败者 future 在 `wait_for_activity().await`
    处被 drop；
  - **路径 H**：健康探针 `timeout()` 到期 drop 仍 park 的 connect future（隧道劣化时即使零客户端
    流量也持续泄漏）。

  修复：在 `connect` 内引入栈上 RAII `SocketGuard`，任何 `?` 早退 / Err 返回 / `await` 取消都会
  触发其 `Drop → remove_socket`；仅在返回 `Ok(Self)` 前 disarm，把所有权交还 `TcpConnection::Drop`。
  一个 guard 同时修复 A/B/H 三条路径。

### 新增

- **指标 `warp_rust_netstack_sockets_active`（gauge）** 与 `NetStack::socket_count()`：暴露 netstack 内
  活跃 socket 数。`create_*_socket` / `remove_socket` 严格配对，活跃连接平稳而该值单调上升即为
  socket 泄漏的直接信号。
- **回归测试** `connect_leak_tests`：无需真实 WARP peer，直接断言路径 A 早退、路径 B 取消后
  `socket_count() == 0`（缺少 guard 时这些测试会失败）。

### 优化 / 变更

- **happy-eyeballs 拨号在隧道无 IPv6 出口时丢弃 v6 候选**（新增 `Tunnel::has_ipv6()`），从源头省掉
  注定 `Ipv6NotSupported` 的无谓拨号（即路径 A 的高频触发）。
- **DNS singleflight** leader 改用 RAII guard 清理 `in_flight` map，取消安全（leader future 被 drop 时
  不再残留条目）。
- **WireGuard 收包回发** 改为在锁外顺序 `send_to().await`，消除原「每个回发包一次 `tokio::spawn`」
  的无界 detached task 与每包一次 `Arc` clone。
- **UDP relay** 纯 v4 associate 不再分配 v6 接收缓冲（省 64 KiB/associate）。
- 内部依赖 `wireguard-netstack` fork 版本 `0.3.1 → 0.3.2`。

### 升级提示

- 升级后**重启**进程以回收已经泄漏的内存（进程内无法回收孤儿 socket）。
- 每条 TCP 连接稳态占用约 `2×tcp_buffer_size`。内存吃紧时可调小：`[warp].tcp_buffer_size`
  `1MiB → 256KiB`、`[limits].relay_buffer_size` `256KiB → 64KiB`。
- 监控新指标 `warp_rust_netstack_sockets_active` 验证修复：它应稳定贴合活跃连接数。

## [0.3.2]

- 七项第二轮修复 + 容器开放代理 BREAKING 收紧（裸 `docker run -p 1080:1080` 默认启动失败，
  需显式 `WARP_RUST_TRUSTED_HOST_NET=1` 或配置 `[server.auth]`）。

## [0.3.1]

- 七项修复 + 高并发吞吐优化（netstack 锁纪律：MB 级 alloc 移出锁外、组合 recv/send 单次取锁等）。

## [0.3.0]

- 提升 WARP SOCKS 吞吐（事件驱动 poll loop、扩大并回压 WG 收发通道）。

## [0.2.3]

- WARP peer endpoint 优先 DNS 解析，IP 仅作 fallback。

[0.4.1]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.4.1
[0.4.0]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.4.0
[0.3.3]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.3
[0.3.2]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.2
[0.3.1]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.1
[0.3.0]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.0
[0.2.3]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.2.3
