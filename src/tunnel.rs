//! WireGuard 隧道句柄。内部持有 `ManagedTunnel`，对外暴露 `dial_tcp` /
//! `bind_udp`；通过 `ArcSwap` 支持热替换，supervisor 重建隧道时不需要把
//! 在飞的拨号请求全部锁住。

use crate::error::{Error, Result};
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use wireguard_netstack::{
    ManagedTunnel, TcpConnection as NetstackTcpConnection, UdpHandle as NetstackUdpHandle,
    WireGuardConfig,
};

/// 上游 TCP 连接租约。除了 netstack socket，还持有创建它的
/// `ManagedTunnel`，使隧道热替换时旧连接的 poll/WireGuard 任务不会
/// 被提前 abort。
pub struct TunnelTcpConnection {
    inner: NetstackTcpConnection,
    _lease: Arc<ManagedTunnel>,
}

impl TunnelTcpConnection {
    pub async fn read(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<usize, wireguard_netstack::Error> {
        self.inner.read(buf).await
    }

    pub async fn write_all(
        &self,
        data: &[u8],
    ) -> std::result::Result<(), wireguard_netstack::Error> {
        self.inner.write_all(data).await
    }

    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

/// 上游 UDP socket 租约，与 [`TunnelTcpConnection`] 相同地保活旧隧道。
pub struct TunnelUdpHandle {
    inner: NetstackUdpHandle,
    _lease: Arc<ManagedTunnel>,
}

impl TunnelUdpHandle {
    pub async fn send_to(
        &self,
        payload: &[u8],
        dest: SocketAddr,
    ) -> std::result::Result<(), wireguard_netstack::Error> {
        self.inner.send_to(payload, dest).await
    }

    pub async fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> std::result::Result<(usize, SocketAddr), wireguard_netstack::Error> {
        self.inner.recv_from(buf, timeout).await
    }
}

pub struct Tunnel {
    /// 重建期间短暂为 `None`；此时拨号会返回 `TunnelNotReady`。
    inner: ArcSwap<Option<Arc<ManagedTunnel>>>,
}

/// 已完成握手的候选隧道，以及它实际使用的配置。WARP ingress 在默认端口
/// 不可达时可能通过备用 UDP 端口建联；调用方必须保存 `config`，否则下一轮
/// reconnect 又会退回原来的坏端口。
pub struct ConnectedTunnel {
    pub managed: ManagedTunnel,
    pub config: WireGuardConfig,
}

// Cloudflare WARP WireGuard ingress 的官方端口集合。API 通常返回 2408；部分
// VPS/运营商会限制该端口，但允许同一 ingress IP 的 IPsec 兼容端口。
const WARP_WG_FALLBACK_PORTS: [u16; 4] = [2408, 500, 1701, 4500];

fn endpoint_ports(original_port: u16) -> Vec<u16> {
    let mut ports = Vec::with_capacity(1 + WARP_WG_FALLBACK_PORTS.len());
    ports.push(original_port);
    ports.extend(
        WARP_WG_FALLBACK_PORTS
            .into_iter()
            .filter(|port| *port != original_port),
    );
    ports
}

impl Tunnel {
    /// 用一个已经建联完成的 `ManagedTunnel` 构造。
    pub fn from_managed(t: ManagedTunnel) -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::new(Arc::new(Some(Arc::new(t)))),
        })
    }

    /// 重新建联，并原子地替换掉原来的隧道。旧隧道的后台任务会随 Drop 被 abort。
    pub async fn rebuild(&self, cfg: WireGuardConfig) -> Result<WireGuardConfig> {
        info!("rebuilding WireGuard tunnel");
        let connected = Self::connect_candidate(cfg).await?;
        let active_config = connected.config.clone();
        self.replace(connected.managed);
        Ok(active_config)
    }

    /// 建立且完成握手的候选隧道，但不改动当前流量。先尝试配置中的端口，
    /// 失败后依次尝试 WARP WireGuard 备用端口。每次失败的 ManagedTunnel 都会
    /// 立即 drop 并 abort 自己的后台任务，不会留下孤儿隧道。
    pub async fn connect_candidate(cfg: WireGuardConfig) -> Result<ConnectedTunnel> {
        let original_port = cfg.peer_endpoint.port();
        let mut failures = Vec::new();
        for (index, port) in endpoint_ports(original_port).into_iter().enumerate() {
            let mut candidate = cfg.clone();
            candidate.peer_endpoint.set_port(port);
            // 原始 API 端点给足标准 10 秒；备用端口各用 5 秒，限制最坏恢复时延。
            let timeout = if index == 0 {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(5)
            };
            match ManagedTunnel::connect_with_timeout(candidate.clone(), timeout).await {
                Ok(managed) => {
                    if port != original_port {
                        warn!(
                            original_port,
                            active_port = port,
                            peer_ip = %candidate.peer_endpoint.ip(),
                            "WireGuard connected through fallback UDP port"
                        );
                    }
                    return Ok(ConnectedTunnel {
                        managed,
                        config: candidate,
                    });
                }
                Err(e) => {
                    failures.push(format!("udp/{port}: {e}"));
                    warn!(
                        peer = %candidate.peer_endpoint,
                        error = %e,
                        "WireGuard endpoint attempt failed"
                    );
                }
            }
        }

        // 全部端口都 `Operation not permitted`（EPERM）几乎总是本机防火墙
        // （iptables/nftables OUTPUT REJECT）拦了到 WARP endpoint 的 UDP，而不是
        // WARP 本身的问题。给一条能直接照做的放行提示。
        let firewall_hint = if failures
            .iter()
            .any(|f| f.contains("Operation not permitted") || f.contains("os error 1"))
        {
            " —— 多为本机防火墙(iptables/nftables OUTPUT)拦截了到 WARP endpoint 的 UDP。\
             请放行出站 UDP 到 162.159.192.0/24 与 188.114.96.0/24 的端口 2408/500/1701/4500\
             （例：`iptables -A OUTPUT -p udp -d 162.159.192.0/24 -j ACCEPT`）"
        } else {
            ""
        };
        Err(Error::other(format!(
            "all WARP WireGuard endpoint ports failed: {}{}",
            failures.join("; "),
            firewall_hint
        )))
    }

    /// 候选隧道和账号都已验证/持久化后，做最后的原子切换。
    pub fn replace(&self, new: ManagedTunnel) {
        let old = self.inner.swap(Arc::new(Some(Arc::new(new))));
        // 旧的 `Arc<ManagedTunnel>` 在最后一个引用消失后才会 drop —— 仍在使用它
        // 的连接因此还可以继续读写，直到自然结束。
        if old.is_some() {
            debug!("previous tunnel dropped");
        }
    }

    /// 通过隧道拨号一个 TCP 目标。处于重建窗口期时返回 `TunnelNotReady`，
    /// SOCKS5 客户端通常会自动重试。
    pub async fn dial_tcp(&self, addr: SocketAddr) -> Result<TunnelTcpConnection> {
        // 拿到一个 `Arc<Option<Arc<ManagedTunnel>>>` 的快照。再从 Option 里 clone
        // 出内层的 `Arc<ManagedTunnel>` —— 这样既不阻塞下一次 swap，也保证当前
        // 这条连接的整个生命周期里底层隧道不会被释放。
        let snapshot = self.inner.load_full();
        let tunnel = match snapshot.as_ref() {
            Some(t) => t.clone(),
            None => return Err(Error::TunnelNotReady),
        };

        let inner = NetstackTcpConnection::connect(tunnel.netstack(), addr)
            .await
            .map_err(|e| Error::Dial {
                addr,
                source: Box::new(e),
            })?;
        Ok(TunnelTcpConnection {
            inner,
            _lease: tunnel,
        })
    }

    /// 在隧道 netstack 内分配一个用户态 IPv4 UDP socket（ephemeral 端口）。
    pub fn bind_udp(&self) -> Result<TunnelUdpHandle> {
        let snapshot = self.inner.load_full();
        let tunnel = match snapshot.as_ref() {
            Some(t) => t.clone(),
            None => return Err(Error::TunnelNotReady),
        };
        let inner = tunnel.netstack().create_udp_socket(0)?;
        Ok(TunnelUdpHandle {
            inner,
            _lease: tunnel,
        })
    }

    /// v0.2.2：在隧道 netstack 内分配一个用户态 IPv6 UDP socket。
    /// 如果 WARP 未提供 IPv6 tunnel 地址（即非双栈），返回 `Ok(None)`。
    pub fn bind_udp_v6(&self) -> Result<Option<TunnelUdpHandle>> {
        let snapshot = self.inner.load_full();
        let tunnel = match snapshot.as_ref() {
            Some(t) => t.clone(),
            None => return Err(Error::TunnelNotReady),
        };
        if tunnel.wg_tunnel().tunnel_ipv6().is_none() {
            return Ok(None);
        }
        let inner = tunnel.netstack().create_udp_socket_with(0, true)?;
        Ok(Some(TunnelUdpHandle {
            inner,
            _lease: tunnel,
        }))
    }

    /// 释放内部隧道（主要供优雅停机调用）。
    pub fn clear(&self) {
        self.inner.store(Arc::new(None));
    }

    /// 隧道当前是否具备 IPv6 出口（WARP 双栈时为 true）。
    ///
    /// 拨号层据此过滤 v6 候选：向无 v6 的隧道拨 v6 目标必定在 netstack 里触发
    /// `Ipv6NotSupported`——既浪费一次 socket 分配，历史上也是泄漏触发点（现已被
    /// `TcpConnection::connect` 的 RAII guard 兜底，但仍应从源头省掉无谓拨号）。
    pub fn has_ipv6(&self) -> bool {
        let snapshot = self.inner.load_full();
        snapshot
            .as_ref()
            .as_ref()
            .map(|t| t.wg_tunnel().tunnel_ipv6().is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_fallback_keeps_api_port_first_without_duplicates() {
        assert_eq!(endpoint_ports(2408), vec![2408, 500, 1701, 4500]);
        assert_eq!(endpoint_ports(500), vec![500, 2408, 1701, 4500]);
        assert_eq!(endpoint_ports(12345), vec![12345, 2408, 500, 1701, 4500]);
    }
}
