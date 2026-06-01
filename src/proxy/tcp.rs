//! SOCKS5 服务端：握手 → CONNECT → 通过 Tunnel 拨号 → 双向 relay。
//!
//! 用 `fast_socks5::server::Socks5ServerProtocol` 的 typestate 自己完成握手、
//! 拿到目标地址，然后用 `Tunnel::dial_tcp` 替代默认的 `TcpStream::connect`，
//! 最后把两端拼起来转发。
//!
//! 因为 `wireguard_netstack::TcpConnection` **没有**实现 `AsyncRead`/
//! `AsyncWrite`，所以这里不能直接用 `tokio::io::copy_bidirectional`，而是
//! 用它裸的 `read`/`write` 方法自己写两个方向的 relay。

use crate::config::{AuthConfig, ServerConfig};
use crate::error::{Error, Result};
use crate::metrics::{
    M_BYTES_DOWN, M_BYTES_UP, M_CONNS_CLOSED, M_CONNS_OPENED, M_UDP_ASSOCIATES_ACTIVE,
};
use crate::proxy::udp;
use crate::tunnel::Tunnel;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use metrics::{counter, gauge};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wireguard_netstack::TcpConnection;

pub async fn serve(
    cfg: ServerConfig,
    tunnel: Arc<Tunnel>,
    cancel: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(cfg.bind).await?;
    info!(addr = %cfg.bind, "SOCKS5 listening");

    let server_ip = cfg.bind.ip();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("SOCKS5 listener stopping");
                return Ok(());
            }
            accept = listener.accept() => {
                let (stream, peer) = accept?;
                let tunnel = tunnel.clone();
                let auth = cfg.auth.clone();
                let parent_cancel = cancel.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, peer, server_ip, tunnel, auth, parent_cancel).await {
                        warn!(%peer, error = %e, "socks5 connection failed");
                    }
                });
            }
        }
    }
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    server_ip: IpAddr,
    tunnel: Arc<Tunnel>,
    auth: Option<AuthConfig>,
    parent_cancel: CancellationToken,
) -> Result<()> {
    // 1. 握手：无鉴权或用户名/密码鉴权
    let proto = match auth {
        None => Socks5ServerProtocol::accept_no_auth(stream).await?,
        Some(a) => {
            let (proto, ok) = Socks5ServerProtocol::accept_password_auth(stream, |u, p| {
                u == a.username && p == a.password
            })
            .await?;
            if !ok {
                warn!(%peer, "socks5 auth failed");
                return Ok(());
            }
            proto
        }
    };

    // 2. 读取 SOCKS5 命令与目标地址
    let (proto, cmd, target) = proto.read_command().await?;

    // 当前支持 CONNECT 与 UDP ASSOCIATE；BIND 拒绝
    match cmd {
        Socks5Command::TCPConnect => {
            // 继续往下走
        }
        Socks5Command::UDPAssociate => {
            return handle_udp_associate(proto, peer, server_ip, tunnel, parent_cancel).await;
        }
        Socks5Command::TCPBind => {
            debug!(%peer, "BIND not supported");
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Ok(());
        }
    }

    // 3. 把目标解析成 IPv4 SocketAddr（netstack 不支持 v6）
    let upstream_addr = match resolve_v4(&target).await {
        Ok(a) => a,
        Err(e) => {
            warn!(%peer, %target, error = %e, "address resolution failed");
            proto.reply_error(&ReplyError::HostUnreachable).await?;
            return Ok(());
        }
    };

    // 4. 通过 WireGuard 隧道拨号
    let upstream = match tunnel.dial_tcp(upstream_addr).await {
        Ok(c) => c,
        Err(e) => {
            warn!(%peer, %upstream_addr, error = %e, "tunnel dial failed");
            // 给客户端一个稍微有用的回复
            let reply = match &e {
                Error::TunnelNotReady => ReplyError::GeneralFailure,
                _ => ReplyError::HostUnreachable,
            };
            proto.reply_error(&reply).await?;
            return Ok(());
        }
    };

    // 5. 告诉客户端连接已经建好。BND.ADDR 直接用上游目标地址是一种实用做法，
    //    与多数 SOCKS5 实现一致
    let client = proto.reply_success(upstream_addr).await?;
    counter!(M_CONNS_OPENED).increment(1);

    debug!(%peer, %upstream_addr, "socks5 connect established");

    // 6. 双向 relay。因为 TcpConnection 不实现 AsyncRead/Write，无法直接用
    //    copy_bidirectional，自己开两个 task
    let (bytes_up, bytes_down) = relay(client, upstream).await?;
    counter!(M_BYTES_UP).increment(bytes_up);
    counter!(M_BYTES_DOWN).increment(bytes_down);
    counter!(M_CONNS_CLOSED).increment(1);
    debug!(%peer, %upstream_addr, bytes_up, bytes_down, "socks5 connection closed");
    Ok(())
}

/// 处理 SOCKS5 UDP ASSOCIATE：本地绑定一个 UDP 中继 socket，把地址告诉客户端，
/// 启动转发 task，然后挂着 TCP 控制流——客户端关 TCP 即视为会话结束，撤下中继。
async fn handle_udp_associate(
    proto: fast_socks5::server::Socks5ServerProtocol<
        TcpStream,
        fast_socks5::server::states::CommandRead,
    >,
    peer: SocketAddr,
    server_ip: IpAddr,
    tunnel: Arc<Tunnel>,
    parent_cancel: CancellationToken,
) -> Result<()> {
    // 中继 socket 绑在和 SOCKS5 服务器同一个 IP 上，这样我们告诉客户端的地址对它而言是可达的
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

    // 回复中继地址；reply_success 消耗 wrapper，把裸 TCP 控制流交还给我们，
    // 我们把它当作 UDP 会话的存活标志一直挂着
    let mut control = proto.reply_success(relay_addr).await?;

    let relay_token = parent_cancel.child_token();

    gauge!(M_UDP_ASSOCIATES_ACTIVE).increment(1.0);

    let relay_handle = {
        let tunnel = tunnel.clone();
        let token = relay_token.clone();
        tokio::spawn(async move {
            if let Err(e) = udp::run_relay(relay_bind, tunnel, token).await {
                warn!(error = %e, "udp relay exited with error");
            }
        })
    };

    // 阻塞在控制 TCP 流上：客户端任何 read（含 EOF）都意味着会话结束。
    // 按 RFC 1928 §6 的要求，UDP 关联的整个生命周期里 TCP 控制流必须保持
    let mut buf = [0u8; 16];
    let _ = control.read(&mut buf).await;
    debug!(%peer, "udp associate: client closed control stream");

    relay_token.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_handle).await;
    gauge!(M_UDP_ASSOCIATES_ACTIVE).decrement(1.0);
    Ok(())
}

/// 把目标解析成 IPv4 SocketAddr。netstack 不支持 IPv6。
async fn resolve_v4(target: &TargetAddr) -> Result<SocketAddr> {
    match target {
        TargetAddr::Ip(sa) => {
            if sa.is_ipv4() {
                Ok(*sa)
            } else {
                Err(Error::DnsNoIpv4(sa.to_string()))
            }
        }
        TargetAddr::Domain(host, port) => {
            let host_port = format!("{host}:{port}");
            let mut iter = lookup_host(&host_port).await?;
            iter.find(|sa| sa.is_ipv4())
                .ok_or_else(|| Error::DnsNoIpv4(host.clone()))
        }
    }
}

/// 双向 relay：tokio TcpStream ↔ TcpConnection
async fn relay(client: TcpStream, upstream: TcpConnection) -> Result<(u64, u64)> {
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let upstream = Arc::new(upstream);
    let up_for_send = upstream.clone();
    let up_for_recv = upstream;

    // client → upstream
    let send = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut total: u64 = 0;
        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // TcpConnection::write_all 返回的是 netstack 的 Error 类型
            up_for_send
                .write_all(&buf[..n])
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            total += n as u64;
        }
        // 半关上游写端，让远端看到 EOF
        up_for_send.shutdown();
        Ok::<u64, std::io::Error>(total)
    });

    // upstream → client
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut total: u64 = 0;
        loop {
            let n = up_for_recv
                .read(&mut buf)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
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
