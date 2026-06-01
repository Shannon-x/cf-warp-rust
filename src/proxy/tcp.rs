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

    // 解析目标 → IPv4（走 Resolver，可隧道内或宿主）
    let upstream_addr = match resolve_target(&resolver, &target).await {
        Ok(a) => a,
        Err(e) => {
            warn!(%peer, %target, error = %e, "address resolution failed");
            proto.reply_error(&ReplyError::HostUnreachable).await?;
            return Ok(());
        }
    };

    // 通过 WireGuard 隧道拨号
    let upstream = match tunnel.dial_tcp(upstream_addr).await {
        Ok(c) => c,
        Err(e) => {
            warn!(%peer, %upstream_addr, error = %e, "tunnel dial failed");
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
    let (bytes_up, bytes_down) =
        relay_with_idle_timeout(client, upstream, limits.idle_timeout).await?;
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

/// v0.2.0：双栈解析。
/// - IP 类型目标：原样返回（v4 或 v6 都可）
/// - Domain：当前先解析为 v4（happy eyeballs 留 v0.2.1）
async fn resolve_target(resolver: &Resolver, target: &TargetAddr) -> Result<SocketAddr> {
    match target {
        TargetAddr::Ip(sa) => Ok(*sa),
        TargetAddr::Domain(host, port) => {
            let sa4 = resolver.resolve_v4(host, *port).await?;
            Ok(SocketAddr::V4(sa4))
        }
    }
}

/// 带 idle 超时的双向 relay。任一方向到达 idle 超时（无字节传输）即中断。
async fn relay_with_idle_timeout(
    client: TcpStream,
    upstream: TcpConnection,
    idle: Duration,
) -> Result<(u64, u64)> {
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let upstream = Arc::new(upstream);
    let up_for_send = upstream.clone();
    let up_for_recv = upstream;

    // client → upstream
    let send = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut total: u64 = 0;
        loop {
            let read_fut = client_r.read(&mut buf);
            let n = match tokio::time::timeout(idle, read_fut).await {
                Ok(r) => r?,
                Err(_) => {
                    counter!(M_IDLE_TIMEOUT).increment(1);
                    break;
                }
            };
            if n == 0 {
                break;
            }
            up_for_send
                .write_all(&buf[..n])
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            total += n as u64;
        }
        up_for_send.shutdown();
        Ok::<u64, std::io::Error>(total)
    });

    // upstream → client
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut total: u64 = 0;
        loop {
            let read_fut = up_for_recv.read(&mut buf);
            let n = match tokio::time::timeout(idle, read_fut).await {
                Ok(r) => r.map_err(|e| std::io::Error::other(e.to_string()))?,
                Err(_) => {
                    counter!(M_IDLE_TIMEOUT).increment(1);
                    break;
                }
            };
            if n == 0 {
                break;
            }
            client_w.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        let _ = client_w.shutdown().await;
        Ok::<u64, std::io::Error>(total)
    });

    let up = send.await.map_err(|e| Error::other(e.to_string()))??;
    let down = recv.await.map_err(|e| Error::other(e.to_string()))??;
    Ok((up, down))
}
