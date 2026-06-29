# 更新日志

本项目的所有重要变更记录于此。版本遵循语义化版本（SemVer）。
日期格式为 `YYYY-MM-DD`。

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

[0.3.3]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.3
[0.3.2]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.2
[0.3.1]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.1
[0.3.0]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.3.0
[0.2.3]: https://github.com/Shannon-x/cf-warp-rust/releases/tag/v0.2.3
