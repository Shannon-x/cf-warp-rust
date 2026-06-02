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

/// 带 idle 超时的双向 relay。任一方向到达 idle 超时（无字节传输）即中断。
///
/// v0.3.1 修复（Bug #3）：两个方向通过 `CancellationToken` 协调，任一方向
/// EOF / 错误 / idle 超时都会立刻 cancel 对端并 shutdown 自己的写半边——
/// 对端从阻塞的 read 上立刻返回 0 字节并退出，不再苦等满 idle_timeout。
/// 主线用 `tokio::try_join!` 并发等两侧（不再串行 await）。
async fn relay_with_idle_timeout(
    client: TcpStream,
    upstream: TcpConnection,
    idle: Duration,
    buf_size: usize,
) -> Result<(u64, u64)> {
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let upstream = Arc::new(upstream);
    let up_for_send = upstream.clone();
    let up_for_recv = upstream;

    let token = CancellationToken::new();
    let send_token = token.clone();
    let recv_token = token.clone();

    // client → upstream
    let send = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        let mut total: u64 = 0;
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
                    total += n as u64;
                }
            }
        }
        // 关 upstream 写半边——让对端 recv read 立刻拿到 0
        up_for_send.shutdown();
        send_token.cancel();
        Ok::<u64, std::io::Error>(total)
    });

    // upstream → client
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        let mut total: u64 = 0;
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
                    total += n as u64;
                }
            }
        }
        // 关 client 写半边——让对端 send 的 client_r.read 立刻拿到 0
        let _ = client_w.shutdown().await;
        recv_token.cancel();
        Ok::<u64, std::io::Error>(total)
    });

    // 并发等两侧；任一侧退出会经 token + shutdown 把对端踢醒。
    // 短 grace 兜底：极端情况下（例如 client 半关但不 reset）对端可能还要
    // 让 read 真正返回 0；500ms 足够，再卡就 abort 对应 task。
    let (up_res, down_res) = match tokio::time::timeout(idle + Duration::from_millis(500), async {
        tokio::try_join!(
            async {
                send.await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            },
            async {
                recv.await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            },
        )
    })
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(Error::other(e.to_string())),
        Err(_) => {
            // 真出现某侧永久卡住——最后兜底，按 0 字节统计该方向，主流程继续
            counter!(M_IDLE_TIMEOUT).increment(1);
            (0, 0)
        }
    };
    Ok((up_res, down_res))
}
