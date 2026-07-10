//! WireGuard 隧道句柄。内部持有 `ManagedTunnel`，对外暴露 `dial_tcp` /
//! `bind_udp`；通过 `ArcSwap` 支持热替换，supervisor 重建隧道时不需要把
//! 在飞的拨号请求全部锁住。

use crate::error::{Error, Result};
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};
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

impl Tunnel {
    /// 用一个已经建联完成的 `ManagedTunnel` 构造。
    pub fn from_managed(t: ManagedTunnel) -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::new(Arc::new(Some(Arc::new(t)))),
        })
    }

    /// 重新建联，并原子地替换掉原来的隧道。旧隧道的后台任务会随 Drop 被 abort。
    pub async fn rebuild(&self, cfg: WireGuardConfig) -> Result<()> {
        info!("rebuilding WireGuard tunnel");
        let new = Self::connect_candidate(cfg).await?;
        self.replace(new);
        Ok(())
    }

    /// 建立且完成握手的候选隧道，但不改动当前流量。
    pub async fn connect_candidate(cfg: WireGuardConfig) -> Result<ManagedTunnel> {
        Ok(ManagedTunnel::connect(cfg).await?)
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
