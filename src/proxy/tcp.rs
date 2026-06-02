//! SOCKS5 服务端：握手 → CONNECT → 通过 Tunnel 拨号 → 双向 relay。
//!
//! v0.1.1 起加入 DoS 防护：
//! - 全局并发上限（Semaphore）
//! - 握手 + read_command 超时
//! - 鉴权失败后强制延迟（防暴破）
//! - relay 双向 idle 超时
//!
//! DNS 通过 `Arc<Resolver>` 统一解析，可在 `[dns]` 配置里切到「隧道内解析」。

use crate::config::{AuthConfig, LimitsConfig, ServerConfig};
use crate::dns::Resolver;
use crate::error::{Error, Result};
use crate::metrics::{
    M_AUTH_FAIL, M_BYTES_DOWN, M_BYTES_UP, M_CONNS_CLOSED, M_CONNS_OPENED, M_CONNS_REJECTED,
    M_HANDSHAKE_TIMEOUT, M_IDLE_TIMEOUT, M_UDP_ASSOCIATES_ACTIVE,
};
use crate::proxy::udp;
use crate::tunnel::Tunnel;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use metrics::{counter, gauge};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wireguard_netstack::TcpConnection;

pub async fn serve(
    cfg: ServerConfig,
    limits: LimitsConfig,
    resolver: Arc<Resolver>,
    tunnel: Arc<Tunnel>,
    cancel: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(cfg.bind).await?;
    info!(
        addr = %cfg.bind,
        max_concurrent = limits.max_concurrent_connections,
        handshake_timeout = ?limits.handshake_timeout,
        idle_timeout = ?limits.idle_timeout,
        "SOCKS5 listening"
    );

    let semaphore = Arc::new(Semaphore::new(limits.max_concurrent_connections));
    let server_ip = cfg.bind.ip();
    let limits = Arc::new(limits);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("SOCKS5 listener stopping");
                return Ok(());
            }
            accept = listener.accept() => {
                let (stream, peer) = accept?;

                // FIX-3 并发上限：满即拒（fail-fast）
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        counter!(M_CONNS_REJECTED).increment(1);
                        warn!(%peer, "连接被拒绝：达到 max_concurrent_connections");
                        drop(stream);
                        continue;
                    }
                };

                let tunnel = tunnel.clone();
                let resolver = resolver.clone();
                let auth = cfg.auth.clone();
                let limits = limits.clone();
                let parent_cancel = cancel.clone();
                tokio::spawn(async move {
                    // permit 在 task 退出时自动 release
                    let _permit = permit;
                    if let Err(e) = handle(
                        stream, peer, server_ip, tunnel, resolver, auth, limits, parent_cancel,
                    )
                    .await
                    {
                        warn!(%peer, error = %e, "socks5 connection failed");
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    server_ip: IpAddr,
    tunnel: Arc<Tunnel>,
    resolver: Arc<Resolver>,
    auth: Option<AuthConfig>,
    limits: Arc<LimitsConfig>,
    parent_cancel: CancellationToken,
) -> Result<()> {
    stream.set_nodelay(true)?;

    // FIX-3 握手超时
    let hs = tokio::time::timeout(
        limits.handshake_timeout,
        handshake_and_read_command(stream, &auth, &limits, peer),
    )
    .await;

    let (proto, cmd, target) = match hs {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            counter!(M_HANDSHAKE_TIMEOUT).increment(1);
            debug!(%peer, "socks5 握手超时");
            return Ok(());
        }
    };

    // 支持的命令分发
    match cmd {
        Socks5Command::TCPConnect => {
            // 继续往下走
        }
        Socks5Command::UDPAssociate => {
            return handle_udp_associate(proto, peer, server_ip, tunnel, resolver, parent_cancel)
                .await;
        }
        Socks5Command::TCPBind => {
            debug!(%peer, "BIND not supported");
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Ok(());
        }
    }

    // v0.2.1：解析为候选列表（v6 优先，v4 兜底）
    let candidates = match resolve_target(&resolver, &target).await {
        Ok(c) => c,
        Err(e) => {
            warn!(%peer, %target, error = %e, "address resolution failed");
            proto.reply_error(&ReplyError::HostUnreachable).await?;
            return Ok(());
        }
    };

    // v0.2.1：候选列表通过 happy eyeballs 拨号；upstream_addr 是实际胜出的地址
    let (upstream_addr, upstream) = match happy_eyeballs_dial(&tunnel, candidates).await {
        Ok(v) => v,
        Err(e) => {
            warn!(%peer, %target, error = %e, "all upstream candidates failed");
            let reply = match &e {
                Error::TunnelNotReady => ReplyError::GeneralFailure,
                _ => ReplyError::HostUnreachable,
            };
            proto.reply_error(&reply).await?;
            return Ok(());
        }
    };

    let client = proto.reply_success(upstream_addr).await?;
    counter!(M_CONNS_OPENED).increment(1);
    debug!(%peer, %upstream_addr, "socks5 connect established");

    // FIX-3 idle 超时 + 双向 relay
    let (bytes_up, bytes_down) = relay_with_idle_timeout(
        client,
        upstream,
        limits.idle_timeout,
        limits.relay_buffer_size,
        limits.relay_close_grace,
    )
    .await?;
    counter!(M_BYTES_UP).increment(bytes_up);
    counter!(M_BYTES_DOWN).increment(bytes_down);
    counter!(M_CONNS_CLOSED).increment(1);
    debug!(%peer, %upstream_addr, bytes_up, bytes_down, "socks5 connection closed");
    Ok(())
}

async fn handshake_and_read_command(
    stream: TcpStream,
    auth: &Option<AuthConfig>,
    limits: &LimitsConfig,
    peer: SocketAddr,
) -> Result<(
    fast_socks5::server::Socks5ServerProtocol<TcpStream, fast_socks5::server::states::CommandRead>,
    Socks5Command,
    TargetAddr,
)> {
    let proto = match auth {
        None => Socks5ServerProtocol::accept_no_auth(stream).await?,
        Some(a) => {
            let (proto, ok) = Socks5ServerProtocol::accept_password_auth(stream, |u, p| {
                u == a.username && p == a.password
            })
            .await?;
            if !ok {
                // FIX-3 鉴权失败延迟（防暴破）
                counter!(M_AUTH_FAIL).increment(1);
                warn!(%peer, "socks5 auth failed; sleeping {:?} before drop", limits.auth_fail_sleep);
                tokio::time::sleep(limits.auth_fail_sleep).await;
                return Err(Error::other("auth failed"));
            }
            proto
        }
    };
    let (proto, cmd, target) = proto.read_command().await?;
    Ok((proto, cmd, target))
}

/// 处理 SOCKS5 UDP ASSOCIATE。
async fn handle_udp_associate(
    proto: fast_socks5::server::Socks5ServerProtocol<
        TcpStream,
        fast_socks5::server::states::CommandRead,
    >,
    peer: SocketAddr,
    server_ip: IpAddr,
    tunnel: Arc<Tunnel>,
    resolver: Arc<Resolver>,
    parent_cancel: CancellationToken,
) -> Result<()> {
    let relay_bind = match UdpSocket::bind(SocketAddr::new(server_ip, 0)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%peer, error = %e, "udp relay bind failed");
            proto.reply_error(&ReplyError::GeneralFailure).await?;
            return Ok(());
        }
    };
    let relay_addr = relay_bind.local_addr()?;
    debug!(%peer, %relay_addr, "udp associate: relay bound");

    let mut control = proto.reply_success(relay_addr).await?;
    let relay_token = parent_cancel.child_token();
    gauge!(M_UDP_ASSOCIATES_ACTIVE).increment(1.0);

    let relay_handle = {
        let tunnel = tunnel.clone();
        let resolver = resolver.clone();
        let token = relay_token.clone();
        tokio::spawn(async move {
            if let Err(e) = udp::run_relay(relay_bind, tunnel, resolver, token).await {
                warn!(error = %e, "udp relay exited with error");
            }
        })
    };

    let mut buf = [0u8; 16];
    let _ = control.read(&mut buf).await;
    debug!(%peer, "udp associate: client closed control stream");

    relay_token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), relay_handle).await;
    gauge!(M_UDP_ASSOCIATES_ACTIVE).decrement(1.0);
    Ok(())
}

/// v0.2.1：双栈解析，返回候选 SocketAddr 列表（v6 优先在前）。
/// - IP 类型目标：原样单条
/// - Domain：并发查 A + AAAA，按 happy-eyeballs 顺序排
async fn resolve_target(resolver: &Resolver, target: &TargetAddr) -> Result<Vec<SocketAddr>> {
    match target {
        TargetAddr::Ip(sa) => Ok(vec![*sa]),
        TargetAddr::Domain(host, port) => resolver.resolve_dual(host, *port).await,
    }
}

/// v0.2.1：Happy Eyeballs Phase 1 风格拨号。
///
/// 候选列表 v6 先 v4 后；试 v6 → 250ms 内没拿到结果，**并发**起 v4 拨号；
/// 任一成功返回，另一个 abort。
///
/// 极简对照 RFC 8305：
/// - 不做地址排序（我们的列表已经 v6 优先）
/// - 单 v6 + 单 v4 双线程而不是逐个全开
/// - 适合 SOCKS5 的快速首字节场景
async fn happy_eyeballs_dial(
    tunnel: &Tunnel,
    candidates: Vec<SocketAddr>,
) -> Result<(SocketAddr, wireguard_netstack::TcpConnection)> {
    if candidates.is_empty() {
        return Err(Error::other("no upstream candidates"));
    }
    if candidates.len() == 1 {
        let addr = candidates[0];
        let conn = tunnel.dial_tcp(addr).await?;
        return Ok((addr, conn));
    }

    // 拆 v6 / v4
    let (v6, v4): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|a| matches!(a, SocketAddr::V6(_)));
    let v6_addr = v6.into_iter().next();
    let v4_addr = v4.into_iter().next();

    // 同时拨；最先成功的赢
    match (v6_addr, v4_addr) {
        (Some(v6), Some(v4)) => {
            let tunnel_clone = tunnel as *const Tunnel;
            // 注意：Tunnel 是 Arc 间接，我们这里通过引用借用，不能 send 给 task。
            // 改成 tokio::select! 同步 await，不 spawn —— 这样不需要 'static。
            let v6_fut = tunnel.dial_tcp(v6);
            let v4_delay = tokio::time::sleep(Duration::from_millis(250));
            tokio::pin!(v6_fut);
            tokio::pin!(v4_delay);
            let _ = tunnel_clone;

            // 先等 v6 250ms；超时就并发 v4
            tokio::select! {
                biased;
                r = &mut v6_fut => {
                    match r {
                        Ok(c) => return Ok((v6, c)),
                        Err(e) => {
                            warn!(%v6, error = %e, "v6 dial failed quickly, fallback v4");
                            return tunnel.dial_tcp(v4).await.map(|c| (v4, c));
                        }
                    }
                }
                _ = &mut v4_delay => {}
            }

            // v6 仍未返回 → 并发 v4
            let v4_fut = tunnel.dial_tcp(v4);
            tokio::pin!(v4_fut);
            tokio::select! {
                biased;
                r = &mut v6_fut => {
                    match r {
                        Ok(c) => Ok((v6, c)),
                        Err(_) => v4_fut.await.map(|c| (v4, c)),
                    }
                }
                r = &mut v4_fut => {
                    match r {
                        Ok(c) => Ok((v4, c)),
                        Err(_) => v6_fut.await.map(|c| (v6, c)),
                    }
                }
            }
        }
        (Some(v6), None) => tunnel.dial_tcp(v6).await.map(|c| (v6, c)),
        (None, Some(v4)) => tunnel.dial_tcp(v4).await.map(|c| (v4, c)),
        (None, None) => Err(Error::other("no upstream candidates")),
    }
}

/// 带 idle 超时的双向 relay。每个方向 read 已经包了 `tokio::time::timeout(idle, ..)`，
/// 因此整条连接不会无限挂；不再额外加「连接总生命周期」timeout。
///
/// v0.3.1 修复（Bug #3）：两个方向通过 `CancellationToken` 协调，任一方向
/// EOF / 错误 / idle 超时都会立刻 cancel 对端并 shutdown 自己的写半边——
/// 对端从阻塞的 read 上立刻返回 0 字节并退出。
///
/// v0.3.2 修复（Bug #1 outer-timeout）：原版的 `timeout(idle + 500ms, try_join!)`
/// 按「连接总生命周期」墙钟计时，任何活过 idle 窗的正常连接都会被错杀；并且
/// 兜底分支 drop 两个 JoinHandle 不会 abort task（tokio 语义：drop = detach），
/// 这两个 task 会带着 socket 继续 detach 跑到 idle 才退，期间还在占 fd 与并发槽。
/// 现在改成：
///   1) 字节计数走 Arc<AtomicU64>，被 abort 也能拿回 partial；
///   2) 不再 try_join!（任一 Err 会丢另一侧）；
///   3) `coordinate_relay` 等第一侧退出 → 给对端 `grace` → 还不退就 abort
///      并 await 回收 JoinError，绝不让 task 泄漏。
///
/// 行为变化（v0.3.2）：不再有「连接总生命周期上限」。长连接（HTTP/2、SSH、
/// WebSocket）只要持续有数据/keepalive 落在 idle 窗内就会一直保活。
///
/// 返回 `(bytes_up, bytes_down)` 是 atomic-snapshot：极端情况下若对端在 grace
/// 超时后被 abort，对应方向可能少计已经写到 socket 但 fetch_add 未发生的字节
/// （write_all 不是 cancel 检测点；只有 write_all Ok 才 fetch_add，所以 atomic
/// 严格 ≤ 实际写出字节，metric 不会虚高）。
async fn relay_with_idle_timeout(
    client: TcpStream,
    upstream: TcpConnection,
    idle: Duration,
    buf_size: usize,
    grace: Duration,
) -> Result<(u64, u64)> {
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let upstream = Arc::new(upstream);
    let up_for_send = upstream.clone();
    let up_for_recv = upstream;

    let token = CancellationToken::new();
    let send_token = token.clone();
    let recv_token = token.clone();

    // 字节计数：放在 atomic，task 被 abort 仍能拿回已经传输的 partial 值。
    // Ordering::Relaxed 足够——`JoinHandle::await` 自身提供 happens-before，
    // load 在两个 task 都 join 完成之后才发生，单调累加无需 SeqCst。
    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));
    let up_bytes_t = up_bytes.clone();
    let down_bytes_t = down_bytes.clone();

    // client → upstream
    let send = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            tokio::select! {
                biased;
                _ = send_token.cancelled() => break,
                r = tokio::time::timeout(idle, client_r.read(&mut buf)) => {
                    let n = match r {
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) => break, // 读出错（含对端 reset）
                        Err(_) => {
                            counter!(M_IDLE_TIMEOUT).increment(1);
                            break;
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    if up_for_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    up_bytes_t.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        // 关 upstream 写半边——让对端 recv read 立刻拿到 0
        up_for_send.shutdown();
        send_token.cancel();
    });

    // upstream → client
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            tokio::select! {
                biased;
                _ = recv_token.cancelled() => break,
                r = tokio::time::timeout(idle, up_for_recv.read(&mut buf)) => {
                    let n = match r {
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) => break,
                        Err(_) => {
                            counter!(M_IDLE_TIMEOUT).increment(1);
                            break;
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    if client_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    down_bytes_t.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        // 关 client 写半边——让对端 send 的 client_r.read 立刻拿到 0
        let _ = client_w.shutdown().await;
        recv_token.cancel();
    });

    // 不再有外层「连接生命周期」总超时；inner per-read idle 超时已经兜底。
    coordinate_relay(send, recv, grace).await;

    Ok((
        up_bytes.load(Ordering::Relaxed),
        down_bytes.load(Ordering::Relaxed),
    ))
}

/// 等任一 JoinHandle 完成；之后给对端 `grace`，到点再 abort 并 await 回收。
///
/// 调用约定：两个 task 自身在退出前已经把对端的 CancellationToken cancel 掉、
/// 把自己写半边 shutdown 掉，所以 `grace` 只是兜底（对端通常在毫秒级就响应）。
/// 被 abort 的 task 仍然会被 `await` 一次——这是 tokio 文档要求的，否则
/// `JoinError` 不会被消费、cleanup 不会跑完。
///
/// 区分 `JoinError`：`is_cancelled()` 是预期的 abort 路径（静默）；`is_panic()`
/// 表示 relay loop 里 panic 了，必须 `warn!` 出来，否则运维不可见。
///
/// 提取成 `pub(crate)` 泛型 helper 是为了单元测试——它不依赖 TcpStream /
/// TcpConnection，可以用普通 `tokio::spawn` 的 `JoinHandle<()>` 直接覆盖。
pub(crate) async fn coordinate_relay(
    mut a: tokio::task::JoinHandle<()>,
    mut b: tokio::task::JoinHandle<()>,
    grace: Duration,
) {
    // v0.3.2 修复：原版 select! 用 `_ =` 把 first-completes 的 JoinResult 吞掉了，
    // 若先完成那侧自己 panic（不是被 abort）panic 信息会被 drop，运维不可见。
    // 改成 `r =` 拿到 JoinResult 再 surface panic；对端的 panic 在它 grace
    // 内完成路径（timeout Ok(Err)）和 abort 路径（timeout Err → await reap）
    // 两条都要 check。`warn_if_panic` helper 把 4 个调用点收敛成一个。
    fn warn_if_panic(r: std::result::Result<(), tokio::task::JoinError>) {
        if let Err(e) = r {
            if e.is_panic() {
                warn!(panic = ?e, "relay task panicked");
            }
        }
    }

    tokio::select! {
        biased;
        ra = &mut a => {
            warn_if_panic(ra);
            // 等 b 退出；grace 内完成 → check panic；超时 → abort + reap
            match tokio::time::timeout(grace, &mut b).await {
                Ok(rb) => warn_if_panic(rb),
                Err(_) => {
                    b.abort();
                    warn_if_panic(b.await);
                }
            }
        }
        rb = &mut b => {
            warn_if_panic(rb);
            match tokio::time::timeout(grace, &mut a).await {
                Ok(ra) => warn_if_panic(ra),
                Err(_) => {
                    a.abort();
                    warn_if_panic(a.await);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AOrdering};
    use tokio::sync::Notify;

    /// 一侧 EOF（立刻退出），另一侧合作（监听 notify 后退出）→ 应在 grace 内退出，
    /// 远低于原版 idle+500ms (≈300s) 的错杀窗口。
    #[tokio::test(flavor = "current_thread")]
    async fn coordinate_relay_peer_exits_within_grace() {
        let notify = Arc::new(Notify::new());
        let n2 = notify.clone();

        let a = tokio::spawn(async move { /* 立刻 EOF */ });
        let b = tokio::spawn(async move {
            // 模拟「被对端踢醒后立刻退出」：等 notify
            n2.notified().await;
        });

        // 让 a 先调度完成；模拟 token.cancel() 通知
        tokio::task::yield_now().await;
        notify.notify_one();

        let start = tokio::time::Instant::now();
        coordinate_relay(a, b, Duration::from_millis(50)).await;
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "peer should exit well under 1s, got {:?}",
            start.elapsed()
        );
    }

    /// 一侧 EOF，另一侧死循环不响应 → coordinate_relay 必须 abort 它。
    /// 验证三条不变量：
    ///   1) 进入 task body（entered=true，证明 task 真的被 scheduled 了）
    ///   2) elapsed ∈ [grace, grace+200ms]（abort 时机正确）
    ///   3) abort 之后 100ms 内 ticks 不再增长（证明 abort 真的生效，task 不再跑）
    /// 这套 sentinel 比原方案（loop sleep 之后写 unreachable_code）严格得多——
    /// 旧方案里 sentinel store 是 dead code，alive 恒为 true，witnesses nothing。
    #[tokio::test(flavor = "current_thread")]
    async fn coordinate_relay_aborts_stuck_peer() {
        let entered = Arc::new(AtomicBool::new(false));
        let ticks = Arc::new(AtomicUsize::new(0));
        let entered_t = entered.clone();
        let ticks_t = ticks.clone();

        let a = tokio::spawn(async move { /* 立刻 EOF */ });
        let b = tokio::spawn(async move {
            entered_t.store(true, AOrdering::Relaxed);
            loop {
                ticks_t.fetch_add(1, AOrdering::Relaxed);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let grace = Duration::from_millis(100);
        let start = tokio::time::Instant::now();
        coordinate_relay(a, b, grace).await;
        let elapsed = start.elapsed();

        // 不变量 1：task 真的 enter 了（spawn 之后被 scheduled）
        assert!(
            entered.load(AOrdering::Relaxed),
            "b task should have entered its body before abort"
        );
        // 不变量 2：elapsed 在 grace 附近（用 250ms 上界容忍调度抖动）
        assert!(
            elapsed >= grace && elapsed < grace + Duration::from_millis(250),
            "abort should happen right after grace, got {:?}",
            elapsed
        );
        // 不变量 3：abort 之后 task 真的不再跑——再等 100ms，ticks 不应继续累加
        let ticks_after_abort = ticks.load(AOrdering::Relaxed);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let ticks_now = ticks.load(AOrdering::Relaxed);
        assert_eq!(
            ticks_now, ticks_after_abort,
            "task should be aborted, but still ticking: {ticks_after_abort} → {ticks_now}"
        );
    }
}
