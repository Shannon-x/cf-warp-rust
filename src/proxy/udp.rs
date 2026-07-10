//! SOCKS5 UDP ASSOCIATE 实现。
//!
//! 客户端 UDP 报文封装格式（RFC 1928 §7）：
//! ```text
//! +----+------+------+----------+----------+----------+
//! |RSV | RSV  | FRAG |   ATYP   | DST.ADDR | DST.PORT |  DATA
//! +----+------+------+----------+----------+----------+
//! ```
//! 仅支持 `FRAG == 0x00`。ATYP：0x01=v4 / 0x03=Domain / 0x04=v6。
//!
//! v0.2.2 起：
//! - 双隧道 UDP socket：tunnel_v4（必有）+ tunnel_v6（可选，双栈时才有）。
//!   按目标地址族选 socket 发包；之前的实现只用一个 v4 socket，发到 v6 dest
//!   会因为 source/dest family 不匹配失败。
//! - Domain ATYP 用 Resolver::resolve_dual 双栈解析，v6 优先（若隧道有 v6
//!   socket），否则回落 v4。

use crate::dns::Resolver;
use crate::error::{Error, Result};
use crate::metrics::M_IDLE_TIMEOUT;
use crate::tunnel::{Tunnel, TunnelUdpHandle};
use metrics::counter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, trace, warn};

/// 双栈 tunnel-side UDP socket 套装
struct TunnelUdpPair {
    v4: Arc<TunnelUdpHandle>,
    v6: Option<Arc<TunnelUdpHandle>>,
}

impl TunnelUdpPair {
    fn new(tunnel: &Tunnel) -> Result<Self> {
        let v4 = Arc::new(tunnel.bind_udp()?);
        let v6 = tunnel.bind_udp_v6()?.map(Arc::new);
        if v6.is_some() {
            debug!("UDP relay 双栈 tunnel socket 就绪（v4+v6）");
        } else {
            debug!("UDP relay 仅 v4 tunnel socket（隧道未提供 IPv6 地址）");
        }
        Ok(Self { v4, v6 })
    }

    /// 选 socket 给 dest 发包
    async fn send_to(&self, payload: &[u8], dest: SocketAddr) -> Result<()> {
        let socket = match dest {
            SocketAddr::V4(_) => &self.v4,
            SocketAddr::V6(_) => self
                .v6
                .as_ref()
                .ok_or_else(|| Error::other("tunnel 无 IPv6 地址；无法向 v6 目标发包"))?,
        };
        socket.send_to(payload, dest).await?;
        Ok(())
    }
}

pub async fn run_relay(
    relay_bind: UdpSocket,
    tunnel: Arc<Tunnel>,
    resolver: Arc<Resolver>,
    allowed_client_ip: IpAddr,
    idle_timeout: Duration,
    parent: CancellationToken,
) -> Result<()> {
    let pair = Arc::new(TunnelUdpPair::new(&tunnel)?);
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let relay_bind = Arc::new(relay_bind);
    let activity = Arc::new(Notify::new());

    // client → tunnel：按 dest family 选 v4/v6 socket
    let mut c2t = AbortOnDropHandle::new({
        let relay_bind = relay_bind.clone();
        let pair = pair.clone();
        let client_addr = client_addr.clone();
        let resolver = resolver.clone();
        let activity = activity.clone();
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
                        if src.ip() != allowed_client_ip {
                            warn!(%src, %allowed_client_ip, "dropping UDP packet from outside this association");
                            continue;
                        }
                        let mut known_client = client_addr.lock().await;
                        if known_client.is_some_and(|known| known != src) {
                            warn!(%src, known = ?*known_client, "dropping UDP packet from a different source port");
                            continue;
                        }
                        *known_client = Some(src);
                        drop(known_client);
                        match forward_client_to_tunnel(&buf[..n], &pair, &resolver).await {
                            Ok(()) => activity.notify_one(),
                            Err(e) => warn!(error = %e, "client→tunnel forward failed"),
                        }
                    }
                }
            }
        })
    });

    // tunnel → client：v4 + v6 socket 并行 recv
    let mut t2c = AbortOnDropHandle::new({
        let relay_bind = relay_bind.clone();
        let pair = pair.clone();
        let client_addr = client_addr.clone();
        let activity = activity.clone();
        let parent = parent.clone();
        tokio::spawn(async move {
            let v4 = pair.v4.clone();
            let v6 = pair.v6.clone();
            // Bug #6：buffer 提到 loop 外复用，避免每轮 65KiB 分配。
            // select! 同时拿 v4/v6 时两个 future 需要互不重叠的可变借用，
            // 所以保留两块独立 buffer。
            // 纯 v4 associate（v6 为 None）下 buf_v6 完全用不到——延迟到有 v6 时再分配，
            // 省掉一块 64KiB 常驻。
            let mut buf_v4 = vec![0u8; 65_535];
            let mut buf_v6 = if v6.is_some() {
                vec![0u8; 65_535]
            } else {
                Vec::new()
            };
            // 回包 framing buffer 复用，避免每个 UDP 数据报都新建 Vec。
            let mut framed = Vec::new();
            enum Pick {
                V4(usize, SocketAddr),
                V6(usize, SocketAddr),
                Timeout,
                Error(String),
            }
            loop {
                if parent.is_cancelled() {
                    break;
                }

                // 同时等 v4 / v6，谁先有谁先发。无 v6 时仅 v4。
                // 用 enum 标记来源，避免把 buffer 移出 select! arm。
                let pick: Pick = if let Some(v6h) = &v6 {
                    let fut_v4 = v4.recv_from(&mut buf_v4, Duration::from_millis(200));
                    let fut_v6 = v6h.recv_from(&mut buf_v6, Duration::from_millis(200));
                    tokio::select! {
                        r = fut_v4 => match r {
                            Ok((n, sa)) => Pick::V4(n, sa),
                            Err(wireguard_netstack::Error::ReadTimeout) => Pick::Timeout,
                            Err(e) => Pick::Error(e.to_string()),
                        },
                        r = fut_v6 => match r {
                            Ok((n, sa)) => Pick::V6(n, sa),
                            Err(wireguard_netstack::Error::ReadTimeout) => Pick::Timeout,
                            Err(e) => Pick::Error(e.to_string()),
                        },
                    }
                } else {
                    match v4.recv_from(&mut buf_v4, Duration::from_millis(200)).await {
                        Ok((n, sa)) => Pick::V4(n, sa),
                        Err(wireguard_netstack::Error::ReadTimeout) => Pick::Timeout,
                        Err(e) => Pick::Error(e.to_string()),
                    }
                };

                let (n, src, buf): (usize, SocketAddr, &[u8]) = match pick {
                    Pick::V4(n, sa) => (n, sa, &buf_v4[..n]),
                    Pick::V6(n, sa) => (n, sa, &buf_v6[..n]),
                    Pick::Timeout => continue, // 两边都 timeout，循环检查 cancel
                    Pick::Error(e) => {
                        warn!(error = %e, "tunnel UDP receive failed");
                        break;
                    }
                };

                let dst = match *client_addr.lock().await {
                    Some(a) => a,
                    None => {
                        trace!("dropping tunnel udp reply, no client address yet");
                        continue;
                    }
                };
                wrap_socks5_udp(&mut framed, src, buf);
                let _ = n; // n 已经反映在 buf 切片长度里
                if let Err(e) = relay_bind.send_to(&framed, dst).await {
                    warn!(error = %e, "tunnel→client send failed");
                    break;
                }
                activity.notify_one();
            }
        })
    });

    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let completed = loop {
        tokio::select! {
            biased;
            _ = parent.cancelled() => break 0u8,
            result = &mut c2t => {
                if let Err(e) = result {
                    warn!(error = ?e, "client→tunnel UDP task failed");
                }
                parent.cancel();
                break 1;
            }
            result = &mut t2c => {
                if let Err(e) = result {
                    warn!(error = ?e, "tunnel→client UDP task failed");
                }
                parent.cancel();
                break 2;
            }
            _ = activity.notified() => {
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            _ = &mut idle => {
                debug!(?idle_timeout, "SOCKS5 UDP association idle timeout");
                counter!(M_IDLE_TIMEOUT).increment(1);
                parent.cancel();
                break 0;
            }
        }
    };
    debug!("SOCKS5 UDP relay shutting down");
    if completed != 1 {
        c2t.abort();
        let _ = c2t.await;
    }
    if completed != 2 {
        t2c.abort();
        let _ = t2c.await;
    }
    Ok(())
}

async fn forward_client_to_tunnel(
    packet: &[u8],
    pair: &TunnelUdpPair,
    resolver: &Resolver,
) -> Result<()> {
    let parsed = parse_socks5_udp_header(packet)?;
    let dest: SocketAddr = match parsed.target {
        UdpTarget::V4(sa) => SocketAddr::V4(sa),
        UdpTarget::V6(sa) => SocketAddr::V6(sa),
        UdpTarget::Domain(host, port) => {
            // 双栈解析 → 候选列表 v6 优先；UDP 无握手，挑第一个可达 family
            let candidates = resolver.resolve_dual(&host, port).await?;
            // 优先匹配 tunnel 实际支持的 family
            let has_v6 = pair.v6.is_some();
            candidates
                .into_iter()
                .find(|c| if has_v6 { true } else { c.is_ipv4() })
                .ok_or_else(|| Error::other(format!("no usable family for {host}")))?
        }
    };
    pair.send_to(parsed.payload, dest).await
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

fn parse_socks5_udp_header(buf: &[u8]) -> Result<ParsedUdp<'_>> {
    if buf.len() < 4 {
        return Err(Error::other("SOCKS5 UDP packet too short"));
    }
    if buf[0] != 0 || buf[1] != 0 {
        return Err(Error::other("SOCKS5 UDP reserved bytes must be zero"));
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
            if port == 0 {
                return Err(Error::other("SOCKS5 UDP destination port must be non-zero"));
            }
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
            if dlen == 0 {
                return Err(Error::other("SOCKS5 UDP domain must be non-empty"));
            }
            if rest.len() < 1 + dlen + 2 {
                return Err(Error::other("SOCKS5 UDP domain header truncated"));
            }
            let host = std::str::from_utf8(&rest[1..1 + dlen])
                .map_err(|_| Error::other("SOCKS5 UDP domain not utf8"))?
                .to_owned();
            let port = u16::from_be_bytes([rest[1 + dlen], rest[1 + dlen + 1]]);
            if port == 0 {
                return Err(Error::other("SOCKS5 UDP destination port must be non-zero"));
            }
            Ok(ParsedUdp {
                target: UdpTarget::Domain(host, port),
                payload: &rest[1 + dlen + 2..],
            })
        }
        0x04 => {
            if rest.len() < 18 {
                return Err(Error::other("SOCKS5 UDP v6 header truncated"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            if port == 0 {
                return Err(Error::other("SOCKS5 UDP destination port must be non-zero"));
            }
            Ok(ParsedUdp {
                target: UdpTarget::V6(SocketAddrV6::new(ip, port, 0, 0)),
                payload: &rest[18..],
            })
        }
        other => Err(Error::other(format!("unknown ATYP 0x{other:02x}"))),
    }
}

/// 双栈版 wrap：按 src family 选 ATYP=0x01 (v4) 或 0x04 (v6)
fn wrap_socks5_udp(out: &mut Vec<u8>, src: SocketAddr, payload: &[u8]) {
    out.clear();
    match src {
        SocketAddr::V4(sa) => {
            out.reserve(10 + payload.len());
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
            out.extend_from_slice(payload);
        }
        SocketAddr::V6(sa) => {
            out.reserve(22 + payload.len());
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
            out.extend_from_slice(payload);
        }
    }
}
