//! SOCKS5 UDP ASSOCIATE 实现。
//!
//! 每一个客户端 UDP 报文的封装格式（RFC 1928 §7）：
//!
//! ```text
//! +----+------+------+----------+----------+----------+
//! |RSV | RSV  | FRAG |   ATYP   | DST.ADDR | DST.PORT |  DATA
//! +----+------+------+----------+----------+----------+
//! | 1  |  1   |  1   |    1     |  var.    |    2     |
//! ```
//!
//! 当前只支持 `FRAG == 0x00`。ATYP 0x01（IPv4）直接用；0x03（Domain）走宿主
//! 机 DNS 解析成第一个 IPv4；0x04（IPv6）拒绝，因为 netstack 是 v4-only。

use crate::error::{Error, Result};
use crate::tunnel::Tunnel;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

/// 为一个 SOCKS5 UDP ASSOCIATE 会话跑一个完整中继；父 token 取消或本身出错
/// 时退出。
///
/// `relay_bind` 已经绑好端口，且地址已经回复给客户端。
pub async fn run_relay(
    relay_bind: UdpSocket,
    tunnel: Arc<Tunnel>,
    parent: CancellationToken,
) -> Result<()> {
    // 隧道侧的用户态 UDP socket：每个 ASSOCIATE 一份
    let tunnel_udp = Arc::new(tunnel.bind_udp()?);

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let relay_bind = Arc::new(relay_bind);

    // client → tunnel 方向
    let c2t = {
        let relay_bind = relay_bind.clone();
        let tunnel_udp = tunnel_udp.clone();
        let client_addr = client_addr.clone();
        let parent = parent.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    biased;
                    _ = parent.cancelled() => break,
                    recv = relay_bind.recv_from(&mut buf) => {
                        let (n, src) = match recv {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(error = %e, "client udp recv error");
                                break;
                            }
                        };
                        *client_addr.lock().await = Some(src);
                        if let Err(e) = forward_client_to_tunnel(&buf[..n], &tunnel_udp).await {
                            warn!(error = %e, "client→tunnel forward failed");
                            // UDP 本来就是不可靠的，单包失败不下中继
                        }
                    }
                }
            }
        })
    };

    // tunnel → client 方向
    let t2c = {
        let relay_bind = relay_bind.clone();
        let tunnel_udp = tunnel_udp.clone();
        let client_addr = client_addr.clone();
        let parent = parent.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                if parent.is_cancelled() {
                    break;
                }
                match tunnel_udp.recv_from(&mut buf, Duration::from_millis(200)).await {
                    Ok((n, src_v4)) => {
                        let dst = match *client_addr.lock().await {
                            Some(a) => a,
                            None => {
                                trace!("dropping tunnel udp reply, no client address known yet");
                                continue;
                            }
                        };
                        let framed = wrap_socks5_udp(src_v4, &buf[..n]);
                        if let Err(e) = relay_bind.send_to(&framed, dst).await {
                            warn!(error = %e, "tunnel→client send failed");
                            break;
                        }
                    }
                    Err(wireguard_netstack::Error::ReadTimeout) => {
                        // 本 tick 没数据，循环去看一下 cancel 然后继续
                    }
                    Err(e) => {
                        warn!(error = %e, "tunnel udp recv error");
                        break;
                    }
                }
            }
        })
    };

    parent.cancelled().await;
    debug!("SOCKS5 UDP relay shutting down");
    c2t.abort();
    t2c.abort();
    Ok(())
}

async fn forward_client_to_tunnel(packet: &[u8], tunnel_udp: &wireguard_netstack::UdpHandle) -> Result<()> {
    let (dest, payload) = parse_socks5_udp(packet)?;
    tunnel_udp.send_to(payload, dest).await?;
    Ok(())
}

/// 解析一段 SOCKS5 UDP 报文头，返回 (目标 v4 地址, 净荷)
fn parse_socks5_udp(buf: &[u8]) -> Result<(SocketAddrV4, &[u8])> {
    if buf.len() < 4 {
        return Err(Error::other("SOCKS5 UDP packet too short"));
    }
    // buf[0..2] = RSV
    if buf[2] != 0x00 {
        return Err(Error::other("SOCKS5 UDP fragmentation not supported"));
    }
    let atyp = buf[3];
    let rest = &buf[4..];
    match atyp {
        0x01 => {
            // IPv4：4 字节地址 + 2 字节端口
            if rest.len() < 6 {
                return Err(Error::other("SOCKS5 UDP v4 header truncated"));
            }
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok((SocketAddrV4::new(ip, port), &rest[6..]))
        }
        0x03 => {
            // Domain：1 字节长度 + 域名 + 2 字节端口
            if rest.is_empty() {
                return Err(Error::other("SOCKS5 UDP domain header truncated"));
            }
            let dlen = rest[0] as usize;
            if rest.len() < 1 + dlen + 2 {
                return Err(Error::other("SOCKS5 UDP domain header truncated"));
            }
            let host = std::str::from_utf8(&rest[1..1 + dlen])
                .map_err(|_| Error::other("SOCKS5 UDP domain not utf8"))?
                .to_owned();
            let port = u16::from_be_bytes([rest[1 + dlen], rest[1 + dlen + 1]]);
            let payload = &rest[1 + dlen + 2..];
            // parse_socks5_udp 是同步函数；这里调用 std::net::ToSocketAddrs
            // （会阻塞）做 DNS。对一个 UDP 数据包来说短暂阻塞可以接受。
            let mut addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
                .map_err(Error::Io)?
                .filter_map(|s| match s {
                    SocketAddr::V4(v4) => Some(v4),
                    SocketAddr::V6(_) => None,
                });
            let dest = addrs
                .next()
                .ok_or_else(|| Error::DnsNoIpv4(host.clone()))?;
            Ok((dest, payload))
        }
        0x04 => Err(Error::other("SOCKS5 UDP IPv6 not supported")),
        other => Err(Error::other(format!("unknown ATYP 0x{other:02x}"))),
    }
}

/// 给一段净荷加上 SOCKS5 UDP 响应头，源地址为 `src`
fn wrap_socks5_udp(src: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // RSV RSV FRAG ATYP=v4
    out.extend_from_slice(&src.ip().octets());
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 异步形式的域名 → IPv4 解析。当前热路径 parse_socks5_udp 走的是同步阻塞
/// 版本；这个保留给未来想把 DNS 也异步化时用。
#[allow(dead_code)]
pub async fn resolve_v4_async(host: &str, port: u16) -> Result<SocketAddrV4> {
    let mut iter = lookup_host((host, port)).await?;
    iter.find_map(|sa| match sa {
        SocketAddr::V4(v4) => Some(v4),
        SocketAddr::V6(_) => None,
    })
    .ok_or_else(|| Error::DnsNoIpv4(host.to_owned()))
}
