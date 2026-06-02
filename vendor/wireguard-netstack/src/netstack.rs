//! Userspace TCP/IP network stack using smoltcp.
//!
//! This module provides a TCP/IP stack that runs entirely in userspace,
//! routing packets through our WireGuard tunnel.
//!
//! # LOCK DISCIPLINE（warp-rust fork v0.3.1，Bug #5 (A)）
//!
//! `NetStackInner` 被一把全局 `parking_lot::Mutex` 守着。这把锁是高并发下
//! 最大的串行化瓶颈 —— **每条连接的 read / write / poll / push_rx 都要争
//! 这同一把锁**。规则：
//!
//! 1. 锁内**只允许** smoltcp 状态机操作：socket get/get_mut、`interface.poll`、
//!    `interface.context`、`sockets.add/remove`、`rx_queue.push/pop`、
//!    `tx_queue.drain` 等。
//! 2. **不允许在锁内做**：
//!    - 任何 `Vec::new` / `vec![..; N]` 等 heap alloc（尤其是 MB 级 socket buffer）
//!    - IP / TCP packet 解析（`Ipv4Packet::new_checked` 等）—— 这只是日志用
//!    - `format!`、`String::push_str`
//!    - 任何 `.await` / 阻塞调用 / 跨线程 channel send
//! 3. 对小操作（can_send/recv + send/recv + may_send/recv）**优先用
//!    `send_with_state` / `recv_with_state` 等组合 API**，一次拿锁做完
//!    多件事，避免一个 hot path 三次进出锁。
//!
//! 长期目标（v0.4）：sharded NetStack —— 按 5-tuple hash 到多个独立
//! NetStack，每个有自己的 SocketSet + Interface。本次（v0.3.1）暂不做
//! 因为 (a) Cloudflare WARP 单 keypair 多 session 兼容性未验证，
//! (b) smoltcp 的 `Interface::poll` 要 `&mut SocketSet`，单 stack 内无法
//! 进一步细化锁。
//!
//! # LOCK DISCIPLINE（warp-rust fork v0.3.1，Bug #5 (A)）
//!
//! `NetStackInner` 被一把全局 `parking_lot::Mutex` 守着。这把锁是高并发下
//! 最大的串行化瓶颈 —— **每条连接的 read / write / poll / push_rx 都要争
//! 这同一把锁**。规则：
//!
//! 1. 锁内**只允许** smoltcp 状态机操作：socket get/get_mut、`interface.poll`、
//!    `interface.context`、`sockets.add/remove`、`rx_queue.push/pop`、
//!    `tx_queue.drain` 等。
//! 2. **不允许在锁内做**：
//!    - 任何 `Vec::new` / `vec![..; N]` 等 heap alloc（尤其是 MB 级 socket buffer）
//!    - IP / TCP packet 解析（`Ipv4Packet::new_checked` 等）—— 这只是日志用
//!    - `format!`、`String::push_str`
//!    - 任何 `.await` / 阻塞调用 / 跨线程 channel send
//! 3. 对小操作（can_send/recv + send/recv + may_send/recv）**优先用
//!    `send_with_state` / `recv_with_state` 等组合 API**，一次拿锁做完
//!    多件事，避免一个 hot path 三次进出锁。
//!
//! 长期目标（v0.4）：sharded NetStack —— 按 5-tuple hash 到多个独立
//! NetStack，每个有自己的 SocketSet + Interface。本次（v0.3.1）暂不做
//! 因为 (a) Cloudflare WARP 单 keypair 多 session 兼容性未验证，
//! (b) smoltcp 的 `Interface::poll` 要 `&mut SocketSet`，单 stack 内无法
//! 进一步细化锁。

use crate::error::{Error, Result};
use crate::wireguard::WireGuardTunnel;
use bytes::BytesMut;
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv4Packet,
    Ipv6Address, TcpPacket,
};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

/// MTU for the virtual interface.
///
/// v0.3.0（warp-rust fork）：对齐 wireproxy / 标准 WireGuard 的 1420。
/// 如果底层路径 PMTU 不足，用户仍可在 config 里 `[warp].mtu = 1280` 回退。
pub const DEFAULT_MTU: usize = 1420;

/// Size of TCP socket buffers.
///
/// 64KiB 会把单连接吞吐限制在 `buffer / RTT`，在 15-50ms 出口 RTT 下只能跑
/// 10-35Mbps。默认提升到 1MiB，实际内存约为每连接 2MiB（rx + tx）。
pub const DEFAULT_TCP_BUFFER_SIZE: usize = 1024 * 1024;

/// A virtual network device that sends/receives through the WireGuard tunnel.
struct VirtualDevice {
    /// Packets ready to be received by smoltcp (from WireGuard).
    rx_queue: VecDeque<BytesMut>,
    /// Packets ready to be sent (to WireGuard).
    tx_queue: VecDeque<BytesMut>,
    /// MTU for this device.
    mtu: usize,
}

impl VirtualDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    /// Add a packet to the receive queue (from WireGuard).
    fn push_rx(&mut self, packet: BytesMut) {
        self.rx_queue.push_back(packet);
    }

    /// Take all packets from the transmit queue (to send via WireGuard).
    fn drain_tx(&mut self) -> Vec<BytesMut> {
        self.tx_queue.drain(..).collect()
    }

    fn prepend_tx(&mut self, mut packets: VecDeque<BytesMut>) {
        while let Some(packet) = packets.pop_back() {
            self.tx_queue.push_front(packet);
        }
    }

    fn has_pending_tx(&self) -> bool {
        !self.tx_queue.is_empty()
    }
}

/// RxToken for smoltcp.
struct VirtualRxToken {
    buffer: BytesMut,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// TxToken for smoltcp.
struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<BytesMut>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = BytesMut::zeroed(len);
        let result = f(&mut buffer);
        self.tx_queue.push_back(buffer);
        result
    }

    fn set_meta(&mut self, _meta: smoltcp::phy::PacketMeta) {
        // No metadata handling needed for virtual device
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.rx_queue.pop_front() {
            Some((
                VirtualRxToken { buffer },
                VirtualTxToken {
                    tx_queue: &mut self.tx_queue,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Shared state for the network stack.
struct NetStackInner {
    interface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
}

/// A userspace TCP/IP network stack.
pub struct NetStack {
    inner: Mutex<NetStackInner>,
    wg_tunnel: Arc<WireGuardTunnel>,
    /// Sender to queue packets for transmission through WireGuard.
    wg_tx: mpsc::Sender<BytesMut>,
    tcp_buffer_size: usize,
    /// PERF-2（warp-rust fork）：事件驱动 poll —— rx/read/write 路径唤醒 poll loop
    poll_notify: tokio::sync::Notify,
    /// 唤醒等待 socket 状态变化的 TCP connect/read/write 调用方。
    state_notify: tokio::sync::Notify,
}

impl NetStack {
    /// Create a new network stack backed by a WireGuard tunnel.
    pub fn new(wg_tunnel: Arc<WireGuardTunnel>) -> Arc<Self> {
        let tunnel_ip = wg_tunnel.tunnel_ip();
        let tunnel_ipv6 = wg_tunnel.tunnel_ipv6();
        let mtu = wg_tunnel.mtu() as usize;
        let tcp_buffer_size = wg_tunnel.tcp_buffer_size();
        let wg_tx = wg_tunnel.outgoing_sender();

        // Create the virtual device with the configured MTU
        let mut device = VirtualDevice::new(mtu);

        // Create the interface configuration
        let config = Config::new(HardwareAddress::Ip);

        // Create the interface
        let mut interface = Interface::new(config, &mut device, Instant::now());

        // v0.2.0：同时配置 v4 与 v6 地址（双栈）
        interface.update_ip_addrs(|addrs| {
            let v4_octets = tunnel_ip.octets();
            addrs
                .push(IpCidr::new(
                    IpAddress::v4(v4_octets[0], v4_octets[1], v4_octets[2], v4_octets[3]),
                    32,
                ))
                .expect("push tunnel v4 cidr");

            if let Some(v6) = tunnel_ipv6 {
                let seg = v6.segments();
                addrs
                    .push(IpCidr::new(
                        IpAddress::Ipv6(Ipv6Address::new(
                            seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                        )),
                        128,
                    ))
                    .expect("push tunnel v6 cidr");
                log::info!("netstack 配置双栈：v4={} v6={}", tunnel_ip, v6);
            }
        });

        // 双栈默认路由：v4 走 0.0.0.0，v6 走 ::（WireGuard 隧道这一侧全部丢给对端）
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 0))
            .expect("v4 default route");
        if tunnel_ipv6.is_some() {
            interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::UNSPECIFIED)
                .expect("v6 default route");
        }

        // Create socket set
        let sockets = SocketSet::new(vec![]);

        let inner = NetStackInner {
            interface,
            device,
            sockets,
        };

        Arc::new(Self {
            inner: Mutex::new(inner),
            wg_tunnel,
            wg_tx,
            tcp_buffer_size,
            poll_notify: tokio::sync::Notify::new(),
            state_notify: tokio::sync::Notify::new(),
        })
    }

    /// 唤醒 poll loop（rx 路径 / read 路径 / write 路径都可以叫）。
    #[inline]
    pub fn kick(&self) {
        self.poll_notify.notify_one();
    }

    #[inline]
    fn notify_state(&self) {
        self.state_notify.notify_waiters();
    }

    async fn wait_for_activity(&self) {
        tokio::select! {
            _ = self.state_notify.notified() => {}
            // Fallback covers the small race where a notification is emitted
            // between the caller's readiness check and registering the waiter.
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }

    /// Create a new TCP socket and return its handle.
    ///
    /// PERF（warp-rust fork v0.3.1，Bug #5 (A)）：
    /// 在 1MiB tcp_buffer_size 配置下，rx+tx 总共要分配 2MiB。如果把
    /// `vec![0u8; ...]` 放在 `inner.lock()` 之内，新连接建立时这把全局锁
    /// 至少要被持有一次 ~毫秒级 alloc + zeroing 的时长，**严重阻塞**正在
    /// 跑流量的所有其它连接 + poll loop。
    ///
    /// 修复：alloc / SocketBuffer 构造 / TcpSocket 配置全部在锁外完成，
    /// 锁内只剩 `sockets.add(socket)` 一次 O(1) slab 插入。
    ///
    /// **锁内只允许 smoltcp state machine 操作；任何 alloc / 日志解析
    /// 都必须在锁外做。** 见模块顶部 LOCK DISCIPLINE 注释。
    pub fn create_tcp_socket(&self) -> SocketHandle {
        // ---- 锁外：分配 buffer + 构造 socket ----
        let rx_buffer = SocketBuffer::new(vec![0u8; self.tcp_buffer_size]);
        let tx_buffer = SocketBuffer::new(vec![0u8; self.tcp_buffer_size]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);

        // ---- 锁内：仅做 slab 插入 ----
        let mut inner = self.inner.lock();
        inner.sockets.add(socket)
    }

    /// Connect a TCP socket to the given address. v0.2.0：v4 与 v6 都支持。
    pub fn connect(&self, handle: SocketHandle, addr: SocketAddr) -> Result<()> {
        let mut inner = self.inner.lock();

        let local_port = 49152 + (rand::random::<u16>() % 16384);

        let (remote, local, log_local) = match addr {
            SocketAddr::V4(v4) => {
                let oct = v4.ip().octets();
                let remote_ep =
                    IpEndpoint::new(IpAddress::v4(oct[0], oct[1], oct[2], oct[3]), v4.port());
                let local_v4 = self.wg_tunnel.tunnel_ip();
                let local_oct = local_v4.octets();
                let local_ep = IpEndpoint::new(
                    IpAddress::v4(local_oct[0], local_oct[1], local_oct[2], local_oct[3]),
                    local_port,
                );
                (remote_ep, local_ep, format!("{}:{}", local_v4, local_port))
            }
            SocketAddr::V6(v6) => {
                // 需要 tunnel_ipv6 才能拨 v6
                let local_v6 = self
                    .wg_tunnel
                    .tunnel_ipv6()
                    .ok_or(Error::Ipv6NotSupported)?;
                let seg = v6.ip().segments();
                let remote_ep = IpEndpoint::new(
                    IpAddress::Ipv6(Ipv6Address::new(
                        seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                    )),
                    v6.port(),
                );
                let local_seg = local_v6.segments();
                let local_ep = IpEndpoint::new(
                    IpAddress::Ipv6(Ipv6Address::new(
                        local_seg[0],
                        local_seg[1],
                        local_seg[2],
                        local_seg[3],
                        local_seg[4],
                        local_seg[5],
                        local_seg[6],
                        local_seg[7],
                    )),
                    local_port,
                );
                (remote_ep, local_ep, format!("[{}]:{}", local_v6, local_port))
            }
        };

        let NetStackInner {
            ref mut interface,
            ref mut sockets,
            ..
        } = *inner;
        let cx = interface.context();
        let socket = sockets.get_mut::<TcpSocket>(handle);
        socket
            .connect(cx, remote, local)
            .map_err(|e| Error::TcpConnectGeneric(format!("TCP connect failed: {}", e)))?;

        log::debug!("TCP socket connecting to {} from {}", addr, log_local);

        // 避免 unused：仅用于 SocketAddrV6 import 抑制
        let _ = std::marker::PhantomData::<SocketAddrV6>;

        Ok(())
    }

    /// Check if a TCP socket is connected.
    pub fn is_connected(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.state() == TcpState::Established
    }

    /// Check if a TCP socket can send data.
    pub fn can_send(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.can_send()
    }

    /// Check if a TCP socket can receive data.
    pub fn can_recv(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        let can = socket.can_recv();
        let recv_queue = socket.recv_queue();
        if recv_queue > 0 {
            log::debug!(
                "Socket can_recv={}, recv_queue={}, state={:?}",
                can,
                recv_queue,
                socket.state()
            );
        }
        can
    }

    /// Check if a TCP socket may send data (connection in progress or established).
    pub fn may_send(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.may_send()
    }

    /// Check if a TCP socket may receive data.
    pub fn may_recv(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.may_recv()
    }

    /// Get the TCP socket state.
    pub fn socket_state(&self, handle: SocketHandle) -> TcpState {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.state()
    }

    /// PERF（warp-rust fork v0.3.1，Bug #5 (A)）：组合 recv —— 单次取锁完成
    /// `can_recv` → `recv_slice` → `may_recv` 三件事，给热路径的
    /// `TcpConnection::read` 用。
    ///
    /// 返回 `(n, may_recv)`：
    /// - `n > 0`：成功读到数据
    /// - `n == 0, may_recv == true`：socket 还活着但暂无数据，调用方应等
    ///   状态通知后重试
    /// - `n == 0, may_recv == false`：对端已 FIN / RST，调用方应返回 EOF
    pub fn recv_with_state(&self, handle: SocketHandle, buf: &mut [u8]) -> Result<(usize, bool)> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);
        let n = if socket.can_recv() {
            socket
                .recv_slice(buf)
                .map_err(|e| Error::TcpRecv(e.to_string()))?
        } else {
            0
        };
        let may = socket.may_recv();
        Ok((n, may))
    }

    /// PERF（warp-rust fork v0.3.1，Bug #5 (A)）：组合 send —— 单次取锁完成
    /// `can_send` → `send_slice` → `may_send`。
    ///
    /// 返回 `(written, may_send)`：
    /// - `written > 0`：放进 tx_buffer 的字节数（调用方应紧接着 `kick()`
    ///   叫醒 poll loop 把包发出去）
    /// - `written == 0, may_send == true`：tx_buffer 满，调用方等通知重试
    /// - `written == 0, may_send == false`：连接已关闭
    pub fn send_with_state(&self, handle: SocketHandle, data: &[u8]) -> Result<(usize, bool)> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);
        let n = if socket.can_send() {
            socket
                .send_slice(data)
                .map_err(|e| Error::TcpSend(e.to_string()))?
        } else {
            0
        };
        let may = socket.may_send();
        Ok((n, may))
    }

    /// Send data on a TCP socket.
    pub fn send(&self, handle: SocketHandle, data: &[u8]) -> Result<usize> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);

        socket
            .send_slice(data)
            .map_err(|e| Error::TcpSend(e.to_string()))
    }

    /// Receive data from a TCP socket.
    pub fn recv(&self, handle: SocketHandle, buffer: &mut [u8]) -> Result<usize> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);

        socket
            .recv_slice(buffer)
            .map_err(|e| Error::TcpRecv(e.to_string()))
    }

    /// Close a TCP socket.
    pub fn close(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);
        socket.close();
    }

    /// Remove a socket from the socket set.
    pub fn remove_socket(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock();
        inner.sockets.remove(handle);
    }

    /// Poll the network stack, processing packets and updating socket states.
    /// Returns true if there was any activity.
    pub fn poll(&self) -> bool {
        // v0.3.1（Bug #5 (A)）：锁内**只做** smoltcp 状态机推进 +
        // device queue 操作。所有 trace 日志移到锁外（length 已经预先取出）。
        let (processed, tx_packets, rx_queue_len) = {
            let mut inner = self.inner.lock();
            let timestamp = Instant::now();

            // Destructure to allow split borrows
            let NetStackInner {
                ref mut interface,
                ref mut device,
                ref mut sockets,
            } = *inner;

            let rx_queue_len = device.rx_queue.len();

            // Poll the interface
            let poll_result = interface.poll(timestamp, device, sockets);
            let processed = poll_result != PollResult::None;

            // Drain transmitted packets and send through WireGuard
            let tx_packets = device.drain_tx();
            (processed, tx_packets, rx_queue_len)
        }; // <- lock released here

        if rx_queue_len > 0 {
            log::trace!("NetStack poll: {} packets in rx_queue", rx_queue_len);
        }
        if processed {
            log::trace!("NetStack poll processed packets");
        }

        let tx_count = tx_packets.len();

        if tx_count > 0 {
            log::trace!("NetStack poll sending {} packets", tx_count);
        }

        let mut iter = tx_packets.into_iter();
        while let Some(packet) = iter.next() {
            // Log outgoing TCP packets at debug level
            if log::log_enabled!(log::Level::Debug) {
                if let Ok(ip_packet) = Ipv4Packet::new_checked(&packet) {
                    let protocol = ip_packet.next_header();
                    if protocol == smoltcp::wire::IpProtocol::Tcp {
                        if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                            let dst_port = tcp_packet.dst_port();
                            let payload_len = tcp_packet.payload().len();

                            let mut flags = String::new();
                            if tcp_packet.syn() {
                                flags.push_str("SYN ");
                            }
                            if tcp_packet.ack() {
                                flags.push_str("ACK ");
                            }
                            if tcp_packet.fin() {
                                flags.push_str("FIN ");
                            }
                            if tcp_packet.rst() {
                                flags.push_str("RST ");
                            }
                            if tcp_packet.psh() {
                                flags.push_str("PSH ");
                            }

                            log::debug!(
                                "TX: {}:{} [{}] {} bytes",
                                ip_packet.dst_addr(),
                                dst_port,
                                flags.trim(),
                                payload_len
                            );
                        }
                    }
                }
            }

            match self.wg_tx.try_send(packet) {
                Ok(()) => {}
                Err(TrySendError::Full(packet)) => {
                    metrics::counter!("warp_rust_wg_tx_backpressure_total").increment(1);
                    let mut unsent = VecDeque::new();
                    unsent.push_back(packet);
                    unsent.extend(iter);
                    let mut inner = self.inner.lock();
                    inner.device.prepend_tx(unsent);
                    break;
                }
                Err(TrySendError::Closed(_packet)) => {
                    metrics::counter!("warp_rust_wg_tx_dropped_total").increment(1);
                    log::trace!("WG outgoing queue closed, dropping packet");
                    break;
                }
            }
        }

        if processed || tx_count > 0 {
            self.notify_state();
        }

        processed
    }

    /// Push a received packet (from WireGuard) into the network stack.
    pub fn push_rx_packet(&self, packet: BytesMut) {
        // Parse and log TCP packet details for debugging
        if log::log_enabled!(log::Level::Debug) {
            if let Ok(ip_packet) = Ipv4Packet::new_checked(&packet) {
                let protocol = ip_packet.next_header();
                if protocol == smoltcp::wire::IpProtocol::Tcp {
                    if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                        let src_port = tcp_packet.src_port();
                        let payload_len = tcp_packet.payload().len();

                        let mut flags = String::new();
                        if tcp_packet.syn() {
                            flags.push_str("SYN ");
                        }
                        if tcp_packet.ack() {
                            flags.push_str("ACK ");
                        }
                        if tcp_packet.fin() {
                            flags.push_str("FIN ");
                        }
                        if tcp_packet.rst() {
                            flags.push_str("RST ");
                        }
                        if tcp_packet.psh() {
                            flags.push_str("PSH ");
                        }

                        log::debug!(
                            "RX: {}:{} [{}] {} bytes",
                            ip_packet.src_addr(),
                            src_port,
                            flags.trim(),
                            payload_len
                        );
                    }
                }
            }
        }

        let mut inner = self.inner.lock();
        inner.device.push_rx(packet);
    }

    /// PERF-2 v2（warp-rust fork v0.2.2）：基于 smoltcp `poll_at` 自适应的
    /// 事件驱动 poll loop。
    ///
    /// 之前的实现用 100µs 兜底 tick——idle 时反而比上游 1ms 多 10×（每秒 10k
    /// 次锁竞争）。现在改成：
    /// - 用 `Interface::poll_at(now, sockets)` 问 smoltcp「下次什么时候需要 poll」
    ///   * `Some(t)` → sleep 到 t（重传定时器等）
    ///   * `None`    → 1 秒兜底（理论上可以更长，但留窗口让 kick() 介入）
    /// - rx/read/write 路径 `kick()` 仍能立即唤醒
    ///
    /// 实测：idle 时几乎不耗 CPU；500Mbps 时立即响应（kick 唤醒）。
    pub async fn run_poll_loop(self: &Arc<Self>) -> Result<()> {
        let started = std::time::Instant::now();
        loop {
            let sleep_dur = {
                let mut inner = self.inner.lock();
                let now =
                    smoltcp::time::Instant::from_millis(started.elapsed().as_millis() as i64);
                let NetStackInner {
                    ref mut interface,
                    ref device,
                    ref sockets,
                } = *inner;
                if device.has_pending_tx() {
                    Duration::from_millis(1)
                } else {
                    match interface.poll_at(now, sockets) {
                        Some(at) if at > now => {
                            let ms = (at - now).total_millis().max(0) as u64;
                            // 限制最长 1 秒，让 kick() 能定期把控制权拿回来
                            Duration::from_millis(ms.min(1000))
                        }
                        Some(_) => Duration::ZERO,
                        None => Duration::from_secs(1),
                    }
                }
            };

            tokio::select! {
                _ = self.poll_notify.notified() => {}
                _ = tokio::time::sleep(sleep_dur) => {}
            }
            self.poll();
        }
    }

    /// Run the receive loop that takes packets from WireGuard and feeds them to the stack.
    pub async fn run_rx_loop(self: &Arc<Self>, mut rx: mpsc::Receiver<BytesMut>) -> Result<()> {
        while let Some(packet) = rx.recv().await {
            log::trace!("NetStack received packet ({} bytes)", packet.len());
            self.push_rx_packet(packet);
            // 叫 poll loop 立即处理；不在这里直接 poll 是因为 poll 内部要拿
            // parking_lot::Mutex，如果 rx_loop 和 poll_loop 都频繁抢锁会有
            // 不必要竞争，让 poll_loop 单线程消费 + 我们 kick 唤醒即可。
            self.kick();
        }

        Ok(())
    }
}

/// A TCP connection through our network stack.
pub struct TcpConnection {
    /// The network stack backing this connection.
    pub netstack: Arc<NetStack>,
    /// The socket handle for this connection.
    pub handle: SocketHandle,
}

impl TcpConnection {
    /// Create a new TCP connection.
    pub async fn connect(netstack: Arc<NetStack>, addr: SocketAddr) -> Result<Self> {
        let handle = netstack.create_tcp_socket();
        netstack.connect(handle, addr)?;
        // 立即叫 poll loop 把 SYN 发出去
        netstack.kick();

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(30);

        loop {
            let state = netstack.socket_state(handle);
            if state == TcpState::Established {
                log::debug!("TCP connection established to {}", addr);
                return Ok(Self { netstack, handle });
            }
            if state == TcpState::Closed || state == TcpState::TimeWait {
                netstack.remove_socket(handle);
                return Err(Error::TcpConnect {
                    addr,
                    message: format!("Connection failed (state: {:?})", state),
                });
            }
            if start.elapsed() > timeout {
                netstack.remove_socket(handle);
                return Err(Error::TcpTimeout);
            }
            netstack.wait_for_activity().await;
        }
    }

    /// Read data from the connection.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // v0.3.0：无硬超时（由上层 idle_timeout 控制），并用 poll loop 的
        // state_notify 唤醒，避免每条连接 100µs 忙轮询抢同一把 netstack 锁。
        //
        // v0.3.1（Bug #5 (A)）：用 `recv_with_state` 把 can_recv + recv +
        // may_recv 合成单次取锁。原版每轮要进出锁 2-3 次，对高并发场景
        // 是显著的争用。
        loop {
            let (n, may_recv) = self.netstack.recv_with_state(self.handle, buf)?;
            if n > 0 {
                return Ok(n);
            }
            if !may_recv {
                return Ok(0); // 对端关闭
            }
            self.netstack.wait_for_activity().await;
        }
    }

    /// Write data to the connection.
    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        let mut written = 0;

        // v0.3.1（Bug #5 (A)）：`send_with_state` 把 can_send + send +
        // may_send 合成单次取锁；写出非零字节后再叫一次 `kick()`（在锁外）
        // 让 poll loop 立即把包发出去。
        while written < data.len() {
            let (n, may_send) = self
                .netstack
                .send_with_state(self.handle, &data[written..])?;
            if n > 0 {
                written += n;
                self.netstack.kick();
                continue;
            }
            if !may_send {
                return Err(Error::ConnectionClosed);
            }
            // tx_buffer 满或暂时不可发送：等状态通知
            self.netstack.wait_for_activity().await;
        }
        Ok(written)
    }

    /// Write all data to the connection.
    pub async fn write_all(&self, data: &[u8]) -> Result<()> {
        let n = self.write(data).await?;
        if n != data.len() {
            return Err(Error::ShortWrite {
                written: n,
                expected: data.len(),
            });
        }
        Ok(())
    }

    /// Shutdown the connection.
    pub fn shutdown(&self) {
        self.netstack.close(self.handle);
    }

    /// Get the socket handle.
    pub fn handle(&self) -> SocketHandle {
        self.handle
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        // FIX-1（warp-rust fork）：上游只调 close()，FIN 发出去但 socket（含 64KB
        // rx + 64KB tx buffer = 128 KB）仍留在 SocketSet 里。每次连接 / 健康探针都
        // 会泄漏一个 socket，长期跑必然撑爆。
        //
        // 修复：close() 标记 FIN → poll() 把 FIN 写到 tx → 立即 remove_socket()
        // 释放 buffer。本端是 client、远端是 Cloudflare WARP，跳过 TIME-WAIT
        // 不会引发任何问题（用的是 ephemeral 端口，远端会自行清理对侧 socket）。
        self.netstack.close(self.handle);
        self.netstack.poll();
        self.netstack.remove_socket(self.handle);
    }
}

// =============================================================================
// UDP 支持 —— 由 warp-rust fork 追加。
// =============================================================================
//
// `UdpHandle` 是 netstack 内的一个用户态 UDP socket。它绑定到 tunnel IP 上
// 由调用方指定的本地端口（传 0 表示 ephemeral），可以向任意 IPv4 目标收发
// 数据报。

/// 每个 UDP socket 的缓冲容量：32 个槽 × 1500 字节，足够支撑交互式
/// DNS/QUIC 流量同时不会让内存膨胀
const UDP_PKT_SLOTS: usize = 32;
const UDP_PAYLOAD_BYTES: usize = 1500 * UDP_PKT_SLOTS;

impl NetStack {
    /// 创建一个绑定到 `(tunnel_ip, local_port)` 的 UDP socket。传 `0` 让实现
    /// 从 ephemeral 范围（49152-65535）随机分配一个端口。
    /// v0.2.0：`prefer_v6 = true` 时优先绑 IPv6 tunnel address（如果可用）。
    pub fn create_udp_socket(self: &Arc<Self>, local_port: u16) -> Result<UdpHandle> {
        self.create_udp_socket_with(local_port, false)
    }

    /// v0.2.0：可指定 v4 / v6 binding。
    pub fn create_udp_socket_with(
        self: &Arc<Self>,
        local_port: u16,
        prefer_v6: bool,
    ) -> Result<UdpHandle> {
        let port = if local_port == 0 {
            49152 + (rand::random::<u16>() % 16384)
        } else {
            local_port
        };

        // PERF（warp-rust fork v0.3.1，Bug #5 (A)）：buffer alloc 留在锁外，
        // 锁内只做 `bind` + `sockets.add` 这两个 smoltcp state machine 操作。
        // UDP payload buffer 是 1500 × 32 = 48KB × 2，比 TCP 的 1MB×2 小得多，
        // 但同一规则照旧 —— 不在锁内做任何 alloc。
        let rx_buffer = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_PKT_SLOTS],
            vec![0u8; UDP_PAYLOAD_BYTES],
        );
        let tx_buffer = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_PKT_SLOTS],
            vec![0u8; UDP_PAYLOAD_BYTES],
        );
        let mut socket = UdpSocket::new(rx_buffer, tx_buffer);

        let (addr, log_str) = if prefer_v6 {
            if let Some(v6) = self.wg_tunnel.tunnel_ipv6() {
                let seg = v6.segments();
                (
                    IpAddress::Ipv6(Ipv6Address::new(
                        seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                    )),
                    format!("[{}]", v6),
                )
            } else {
                let v4 = self.wg_tunnel.tunnel_ip();
                let oct = v4.octets();
                (
                    IpAddress::v4(oct[0], oct[1], oct[2], oct[3]),
                    v4.to_string(),
                )
            }
        } else {
            let v4 = self.wg_tunnel.tunnel_ip();
            let oct = v4.octets();
            (
                IpAddress::v4(oct[0], oct[1], oct[2], oct[3]),
                v4.to_string(),
            )
        };

        let listen = IpListenEndpoint {
            addr: Some(addr),
            port,
        };

        // bind 只改 socket 自身状态，无需 SocketSet，可以在锁外做。
        socket
            .bind(listen)
            .map_err(|e| Error::TcpConnectGeneric(format!("UDP bind failed: {}", e)))?;

        // 锁内：仅做 slab 插入。
        let handle = {
            let mut inner = self.inner.lock();
            inner.sockets.add(socket)
        };
        log::debug!("UDP socket bound to {}:{}", log_str, port);

        Ok(UdpHandle {
            netstack: Arc::clone(self),
            handle,
            local_port: port,
        })
    }

    /// 通过 `handle` 向 `dest` 发送一个 UDP 数据报。Ok 表示 smoltcp 已经接收
    /// 净荷；后续由 netstack 的 poll 循环把它真正发出去。
    /// v0.2.0：支持 v4 与 v6 目标。
    pub fn udp_send_to(&self, handle: SocketHandle, payload: &[u8], dest: SocketAddr) -> Result<()> {
        let endpoint = match dest {
            SocketAddr::V4(v4) => {
                let oct = v4.ip().octets();
                IpEndpoint::new(IpAddress::v4(oct[0], oct[1], oct[2], oct[3]), v4.port())
            }
            SocketAddr::V6(v6) => {
                let seg = v6.ip().segments();
                IpEndpoint::new(
                    IpAddress::Ipv6(Ipv6Address::new(
                        seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                    )),
                    v6.port(),
                )
            }
        };
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<UdpSocket>(handle);
        socket
            .send_slice(payload, endpoint)
            .map_err(|e| Error::TcpSend(format!("UDP send: {}", e)))?;
        Ok(())
    }

    /// 尝试从 `handle` 取出一个数据报。当前没有数据时返回 `Ok(None)`，
    /// 调用方需要稍后重试。v0.2.0：返回的源地址支持 v4/v6。
    pub fn udp_try_recv(
        &self,
        handle: SocketHandle,
        buf: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr)>> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<UdpSocket>(handle);
        if !socket.can_recv() {
            return Ok(None);
        }
        let (n, meta) = socket
            .recv_slice(buf)
            .map_err(|e| Error::TcpRecv(format!("UDP recv: {}", e)))?;
        let src = match meta.endpoint.addr {
            IpAddress::Ipv4(a) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(a.octets()[0], a.octets()[1], a.octets()[2], a.octets()[3]),
                meta.endpoint.port,
            )),
            IpAddress::Ipv6(a) => {
                let oct = a.octets();
                let v6 = Ipv6Addr::new(
                    u16::from_be_bytes([oct[0], oct[1]]),
                    u16::from_be_bytes([oct[2], oct[3]]),
                    u16::from_be_bytes([oct[4], oct[5]]),
                    u16::from_be_bytes([oct[6], oct[7]]),
                    u16::from_be_bytes([oct[8], oct[9]]),
                    u16::from_be_bytes([oct[10], oct[11]]),
                    u16::from_be_bytes([oct[12], oct[13]]),
                    u16::from_be_bytes([oct[14], oct[15]]),
                );
                SocketAddr::V6(SocketAddrV6::new(v6, meta.endpoint.port, 0, 0))
            }
        };
        Ok(Some((n, src)))
    }
}

/// 一个跑在 netstack 内部的用户态 UDP socket。Drop 时释放底层的 smoltcp socket。
pub struct UdpHandle {
    netstack: Arc<NetStack>,
    handle: SocketHandle,
    local_port: u16,
}

impl UdpHandle {
    /// 当前 socket 绑定在 tunnel 接口上的本地端口
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// 发送一个数据报，并主动 poll 一次让 WireGuard 立即把它转出去
    /// v0.2.0：接受 SocketAddr（v4/v6 都可）
    pub async fn send_to(&self, payload: &[u8], dest: SocketAddr) -> Result<()> {
        self.netstack.udp_send_to(self.handle, payload, dest)?;
        self.netstack.poll();
        Ok(())
    }

    /// 接收一个数据报。最多等待 `timeout`；超时返回 `Err(ReadTimeout)`。
    /// v0.3.x：与 TCP read 对齐 —— 不再 1ms 忙轮询，也不在 hot path 主动
    /// `poll()`（会跟 poll loop 抢 inner 锁）。改成先 try_recv，无数据时挂
    /// 在 `state_notify` 上等 poll loop 唤醒；用一个总 deadline 控制超时。
    /// v0.2.0：返回 SocketAddr（v4/v6）。
    pub async fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> Result<(usize, SocketAddr)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(got) = self.netstack.udp_try_recv(self.handle, buf)? {
                return Ok(got);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(Error::ReadTimeout);
            }
            // 等到 poll loop 处理过 rx（state_notify）或到 deadline 为止。
            // wait_for_activity 自身带 1ms fallback 防 notify 漏掉，这里再加
            // 一个 deadline sleep 用于上层 cancel 检查。
            tokio::select! {
                _ = self.netstack.wait_for_activity() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    // 让出后下一轮 try_recv + 再判 deadline，避免 sleep 与
                    // 通知 race 时直接 ReadTimeout 漏一次数据。
                }
            }
        }
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        self.netstack.remove_socket(self.handle);
        self.netstack.poll();
    }
}
