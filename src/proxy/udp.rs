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
//! 当前只支持 `FRAG == 0x00`。ATYP 0x01（IPv4）直接用；0x03（Domain）走
//! `Resolver` 解析（可配置 system / tunnel 模式）；0x04（IPv6）拒绝。
//!
//! v0.1.1 起 Domain 解析改为异步（之前 parse_socks5_udp 同步阻塞做 DNS）。

use crate::dns::Resolver;
use crate::error::{Error, Result};
use crate::tunnel::Tunnel;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

/// 为一个 SOCKS5 UDP ASSOCIATE 会话跑一个完整中继；父 token 取消或本身出错
/// 时退出。
pub async fn run_relay(
    relay_bind: UdpSocket,
    tunnel: Arc<Tunnel>,
    resolver: Arc<Resolver>,
    parent: CancellationToken,
) -> Result<()> {
    let tunnel_udp = Arc::new(tunnel.bind_udp()?);
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let relay_bind = Arc::new(relay_bind);

    // client → tunnel
    let c2t = {
        let relay_bind = relay_bind.clone();
        let tunnel_udp = tunnel_udp.clone();
        let client_addr = client_addr.clone();
        let resolver = resolver.clone();
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
                            Err(e) => { warn!(error = %e, "client udp recv error"); break; }
                        };
                        *client_addr.lock().await = Some(src);
                        if let Err(e) = forward_client_to_tunnel(&buf[..n], &tunnel_udp, &resolver).await {
                            warn!(error = %e, "client→tunnel forward failed");
                        }
                    }
                }
            }
        })
    };

    // tunnel → client
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
                match tunnel_udp
                    .recv_from(&mut buf, Duration::from_millis(200))
                    .await
                {
                    Ok((n, src)) => {
                        let dst = match *client_addr.lock().await {
                            Some(a) => a,
                            None => {
                                trace!("dropping tunnel udp reply, no client address yet");
                                continue;
                            }
                        };
                        let framed = wrap_socks5_udp(src, &buf[..n]);
                        if let Err(e) = relay_bind.send_to(&framed, dst).await {
                            warn!(error = %e, "tunnel→client send failed");
                            break;
                        }
                    }
                    Err(wireguard_netstack::Error::ReadTimeout) => {}
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

async fn forward_client_to_tunnel(
    packet: &[u8],
    tunnel_udp: &wireguard_netstack::UdpHandle,
    resolver: &Resolver,
) -> Result<()> {
    let parsed = parse_socks5_udp_header(packet)?;
    let dest: SocketAddr = match parsed.target {
        UdpTarget::V4(sa) => SocketAddr::V4(sa),
        UdpTarget::V6(sa) => SocketAddr::V6(sa),
        UdpTarget::Domain(host, port) => {
            // v0.2.0：通过 Resolver 解析，先返 v4；后续可加 happy eyeballs
            SocketAddr::V4(resolver.resolve_v4(&host, port).await?)
        }
    };
    tunnel_udp.send_to(parsed.payload, dest).await?;
    Ok(())
}

enum UdpTarget {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String, u16),
}

struct ParsedUdp<'a> {
    target: UdpTarget,
    payload: &'a [u8],
}

/// 解析一段 SOCKS5 UDP 报文头，返回目标与净荷（同步、无 IO）。
fn parse_socks5_udp_header(buf: &[u8]) -> Result<ParsedUdp<'_>> {
    if buf.len() < 4 {
        return Err(Error::other("SOCKS5 UDP packet too short"));
    }
    if buf[2] != 0x00 {
        return Err(Error::other("SOCKS5 UDP fragmentation not supported"));
    }
    let atyp = buf[3];
    let rest = &buf[4..];
    match atyp {
        0x01 => {
            if rest.len() < 6 {
                return Err(Error::other("SOCKS5 UDP v4 header truncated"));
            }
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok(ParsedUdp {
                target: UdpTarget::V4(SocketAddrV4::new(ip, port)),
                payload: &rest[6..],
            })
        }
        0x03 => {
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
            Ok(ParsedUdp {
                target: UdpTarget::Domain(host, port),
                payload: &rest[1 + dlen + 2..],
            })
        }
        0x04 => {
            // v0.2.0：IPv6（16 字节地址 + 2 字节端口）
            if rest.len() < 18 {
                return Err(Error::other("SOCKS5 UDP v6 header truncated"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok(ParsedUdp {
                target: UdpTarget::V6(SocketAddrV6::new(ip, port, 0, 0)),
                payload: &rest[18..],
            })
        }
        other => Err(Error::other(format!("unknown ATYP 0x{other:02x}"))),
    }
}

/// v0.2.0：双栈版 wrap，自动按 src 类型选 ATYP=0x01 或 0x04
fn wrap_socks5_udp(src: SocketAddr, payload: &[u8]) -> Vec<u8> {
    match src {
        SocketAddr::V4(sa) => {
            let mut out = Vec::with_capacity(10 + payload.len());
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // RSV RSV FRAG ATYP=v4
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        SocketAddr::V6(sa) => {
            let mut out = Vec::with_capacity(22 + payload.len());
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // RSV RSV FRAG ATYP=v6
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
    }
}
