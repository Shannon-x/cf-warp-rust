//! WireGuard 隧道句柄。内部持有 `ManagedTunnel`，对外暴露 `dial_tcp` /
//! `bind_udp`；通过 `ArcSwap` 支持热替换，supervisor 重建隧道时不需要把
//! 在飞的拨号请求全部锁住。

use crate::error::{Error, Result};
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};
use wireguard_netstack::{ManagedTunnel, TcpConnection, UdpHandle, WireGuardConfig};

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
        let new = ManagedTunnel::connect(cfg).await?;
        let old = self.inner.swap(Arc::new(Some(Arc::new(new))));
        // 旧的 `Arc<ManagedTunnel>` 在最后一个引用消失后才会 drop —— 仍在使用它
        // 的连接因此还可以继续读写，直到自然结束。
        if old.is_some() {
            debug!("previous tunnel dropped");
        }
        Ok(())
    }

    /// 通过隧道拨号一个 TCP 目标。处于重建窗口期时返回 `TunnelNotReady`，
    /// SOCKS5 客户端通常会自动重试。
    pub async fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpConnection> {
        // 拿到一个 `Arc<Option<Arc<ManagedTunnel>>>` 的快照。再从 Option 里 clone
        // 出内层的 `Arc<ManagedTunnel>` —— 这样既不阻塞下一次 swap，也保证当前
        // 这条连接的整个生命周期里底层隧道不会被释放。
        let snapshot = self.inner.load_full();
        let tunnel = match snapshot.as_ref() {
            Some(t) => t.clone(),
            None => return Err(Error::TunnelNotReady),
        };

        TcpConnection::connect(tunnel.netstack(), addr)
            .await
            .map_err(|e| Error::Dial {
                addr,
                source: Box::new(e),
            })
    }

    /// 在隧道 netstack 内分配一个用户态 IPv4 UDP socket（ephemeral 端口）。
    pub fn bind_udp(&self) -> Result<UdpHandle> {
        let snapshot = self.inner.load_full();
        let tunnel = match snapshot.as_ref() {
            Some(t) => t.clone(),
            None => return Err(Error::TunnelNotReady),
        };
        Ok(tunnel.netstack().create_udp_socket(0)?)
    }

    /// v0.2.2：在隧道 netstack 内分配一个用户态 IPv6 UDP socket。
    /// 如果 WARP 未提供 IPv6 tunnel 地址（即非双栈），返回 `Ok(None)`。
    pub fn bind_udp_v6(&self) -> Result<Option<UdpHandle>> {
        let snapshot = self.inner.load_full();
        let tunnel = match snapshot.as_ref() {
            Some(t) => t.clone(),
            None => return Err(Error::TunnelNotReady),
        };
        if tunnel.wg_tunnel().tunnel_ipv6().is_none() {
            return Ok(None);
        }
        Ok(Some(tunnel.netstack().create_udp_socket_with(0, true)?))
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

    /// 给后续探针留出的接口：距上一次 WireGuard 握手的时长。
    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        let snapshot = self.inner.load_full();
        snapshot
            .as_ref()
            .as_ref()
            .and_then(|t| t.time_since_last_handshake())
    }
}
