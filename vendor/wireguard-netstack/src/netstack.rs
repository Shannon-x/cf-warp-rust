//! Userspace TCP/IP network stack using smoltcp.
//!
//! This module provides a TCP/IP stack that runs entirely in userspace,
//! routing packets through our WireGuard tunnel.
//!
//! # LOCK DISCIPLINE（warp-rust fork v0.4.0）
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
//! 更进一步的 sharded NetStack 需要先验证 Cloudflare WARP 单 keypair 多
//! session 兼容性；未验证前保持单 stack，并通过每 socket 事件唤醒压低锁竞争。

use crate::error::{Error, Result};
use crate::wireguard::WireGuardTunnel;
use bytes::BytesMut;
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata,
    SendError as UdpSendError, Socket as UdpSocket,
};
use smoltcp::socket::Socket;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv4Packet,
    Ipv6Address, TcpPacket,
};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

/// MTU for the virtual interface.
///
/// v0.4.5（warp-rust fork）：默认 1280，覆盖常见 VPS 叠加隧道/PPPoE 路径，
/// 并与主程序、安装器、示例和全部启动脚本保持一致。确认 PMTU 足够时上层仍可
/// 显式配置更大值。
pub const DEFAULT_MTU: usize = 1280;

/// Size of TCP socket buffers.
///
/// 256KiB 在常见 15-50ms RTT 下仍可提供约 40-140Mbps 的单连接窗口，同时把
/// 每连接的固定预分配从 2MiB 降到 512KiB（rx + tx）。需要跑单流超高速时可由
/// 上层配置调大；高并发服务不应默认按 1MiB/方向预分配。
pub const DEFAULT_TCP_BUFFER_SIZE: usize = 256 * 1024;

// 用户态 stack 不与宿主内核端口空间冲突；使用 Linux 常见动态范围
// 32768..=65535，让 16384 并发配合 2 路 Happy Eyeballs 仍有完整容量。
const EPHEMERAL_PORT_START: u16 = 32_768;
const EPHEMERAL_PORT_COUNT: usize = 32_768;
const MAX_DEVICE_QUEUE_PACKETS: usize = 8192;

/// 固定大小的临时端口分配器。旧实现每次随机抽一个端口，在大量连接到同一目标时
/// 很快发生生日碰撞，生成相同四元组；smoltcp 随后会把回包交给错误的 socket。
/// 位图保证端口在释放前绝不复用，也不会为了追踪端口产生额外堆分配。
struct EphemeralPortAllocator {
    used: [u64; EPHEMERAL_PORT_COUNT / 64],
    next: usize,
}

impl EphemeralPortAllocator {
    fn new() -> Self {
        Self {
            used: [0; EPHEMERAL_PORT_COUNT / 64],
            next: (rand::random::<u16>() as usize) % EPHEMERAL_PORT_COUNT,
        }
    }

    fn allocate(&mut self) -> Option<u16> {
        for offset in 0..EPHEMERAL_PORT_COUNT {
            let idx = (self.next + offset) % EPHEMERAL_PORT_COUNT;
            let word = idx / 64;
            let bit = 1u64 << (idx % 64);
            if self.used[word] & bit == 0 {
                self.used[word] |= bit;
                self.next = (idx + 1) % EPHEMERAL_PORT_COUNT;
                return Some(EPHEMERAL_PORT_START + idx as u16);
            }
        }
        None
    }

    fn release(&mut self, port: u16) {
        let Some(idx) = port
            .checked_sub(EPHEMERAL_PORT_START)
            .map(usize::from)
            .filter(|idx| *idx < EPHEMERAL_PORT_COUNT)
        else {
            return;
        };
        self.used[idx / 64] &= !(1u64 << (idx % 64));
    }
}

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
    fn push_rx(&mut self, packet: BytesMut) -> bool {
        if self.rx_queue.len() >= MAX_DEVICE_QUEUE_PACKETS {
            return false;
        }
        self.rx_queue.push_back(packet);
        true
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
        if self.tx_queue.len() >= MAX_DEVICE_QUEUE_PACKETS {
            return None;
        }
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
        (self.tx_queue.len() < MAX_DEVICE_QUEUE_PACKETS).then_some(VirtualTxToken {
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

/// 只唤醒状态真正就绪的对应 socket，避免全局 `notify_waiters` 导致 N 条连接在
/// 每个包上同时抢一把 NetStack 锁（惊群）。
///
/// 任何在锁内推进过 `Interface::poll` 的地方都必须调用它——`NetStack::poll` 只在
/// 自己那次 poll 返回非 `None` 时唤醒，如果别处已经把 ingress 消化掉了，poll loop
/// 随后会拿到 `PollResult::None` 而静默跳过唤醒，读者要等到下一个包或 1 秒兜底
/// 才会醒。
fn notify_ready_sockets(
    sockets: &SocketSet<'static>,
    signals: &HashMap<SocketHandle, Arc<SocketSignals>>,
) {
    for (handle, socket) in sockets.iter() {
        let Some(signal) = signals.get(&handle) else {
            continue;
        };
        match socket {
            Socket::Tcp(socket) => {
                let state = socket.state();
                if matches!(
                    state,
                    TcpState::Established | TcpState::Closed | TcpState::TimeWait
                ) {
                    signal.connect.notify_waiters();
                }
                if socket.can_recv() || !socket.may_recv() {
                    signal.read.notify_waiters();
                }
                if socket.can_send() || !socket.may_send() {
                    signal.write.notify_waiters();
                }
            }
            Socket::Udp(socket) => {
                if socket.can_recv() {
                    signal.udp_read.notify_waiters();
                }
                if socket.can_send() {
                    signal.udp_write.notify_waiters();
                }
            }
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }
}

/// Shared state for the network stack.
struct NetStackInner {
    interface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    signals: HashMap<SocketHandle, Arc<SocketSignals>>,
}

#[derive(Default)]
struct SocketSignals {
    connect: tokio::sync::Notify,
    read: tokio::sync::Notify,
    write: tokio::sync::Notify,
    udp_read: tokio::sync::Notify,
    udp_write: tokio::sync::Notify,
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
    /// TCP 与 UDP 分属不同的传输层端口空间，各自独立分配。
    tcp_ports: Mutex<EphemeralPortAllocator>,
    udp_ports: Mutex<EphemeralPortAllocator>,
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
            signals: HashMap::new(),
        };

        Arc::new(Self {
            inner: Mutex::new(inner),
            wg_tunnel,
            wg_tx,
            tcp_buffer_size,
            poll_notify: tokio::sync::Notify::new(),
            tcp_ports: Mutex::new(EphemeralPortAllocator::new()),
            udp_ports: Mutex::new(EphemeralPortAllocator::new()),
        })
    }

    /// 唤醒 poll loop（rx 路径 / read 路径 / write 路径都可以叫）。
    #[inline]
    pub fn kick(&self) {
        self.poll_notify.notify_one();
    }

    fn allocate_tcp_port(&self) -> Result<u16> {
        match self.tcp_ports.lock().allocate() {
            Some(port) => Ok(port),
            None => {
                // 这是单实例的架构天花板，不是配置能调大的东西：端口池固定
                // 32768 个。撞上它说明并发 TCP 连接已接近该上限，唯一的出路是
                // 横向拆分（多实例 + 上游负载均衡），所以错误信息必须说清楚，
                // 不能让运维以为再调大 max_concurrent_connections 就行。
                metrics::counter!(
                    "warp_rust_ephemeral_port_exhausted_total",
                    "proto" => "tcp"
                )
                .increment(1);
                Err(Error::TcpConnectGeneric(format!(
                    "TCP ephemeral port range exhausted ({EPHEMERAL_PORT_COUNT} ports); \
                     this is the per-instance architectural ceiling — run multiple \
                     instances behind a load balancer instead of raising limits"
                )))
            }
        }
    }

    fn release_tcp_port(&self, port: u16) {
        self.tcp_ports.lock().release(port);
    }

    fn allocate_udp_port(&self) -> Result<u16> {
        self.udp_ports
            .lock()
            .allocate()
            .ok_or_else(|| Error::TcpConnectGeneric("UDP ephemeral port range exhausted".into()))
    }

    fn release_udp_port(&self, port: u16) {
        self.udp_ports.lock().release(port);
    }

    /// Create a new TCP socket and return its handle.
    ///
    /// PERF（warp-rust fork v0.3.1，Bug #5 (A)）：
    /// 在较大的 tcp_buffer_size 配置下，rx+tx 会产生显著固定预分配。如果把
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
        let signals = Arc::new(SocketSignals::default());
        let handle = {
            let mut inner = self.inner.lock();
            let handle = inner.sockets.add(socket);
            inner.signals.insert(handle, signals);
            handle
        };
        // 可观测性：活跃 socket 数。create_tcp_socket / create_udp_socket_with 的每次
        // 分配都 +1，remove_socket 每次 -1，严格配对。若活跃连接数平稳而此 gauge 仍
        // 单调上升，即为 socket（含 2×tcp_buffer_size buffer）泄漏的直接信号。
        metrics::gauge!("warp_rust_netstack_sockets_active").increment(1.0);
        handle
    }

    /// Connect a TCP socket to the given address. v0.2.0：v4 与 v6 都支持。
    pub fn connect(&self, handle: SocketHandle, addr: SocketAddr) -> Result<u16> {
        let local_port = self.allocate_tcp_port()?;

        let endpoints = match addr {
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
                let local_v6 = self.wg_tunnel.tunnel_ipv6().ok_or(Error::Ipv6NotSupported);
                let local_v6 = match local_v6 {
                    Ok(ip) => ip,
                    Err(e) => {
                        self.release_tcp_port(local_port);
                        return Err(e);
                    }
                };
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
                (
                    remote_ep,
                    local_ep,
                    format!("[{}]:{}", local_v6, local_port),
                )
            }
        };
        let (remote, local, log_local) = endpoints;

        let mut inner = self.inner.lock();

        let NetStackInner {
            ref mut interface,
            ref mut sockets,
            ..
        } = *inner;
        let cx = interface.context();
        let socket = sockets.get_mut::<TcpSocket>(handle);
        if let Err(e) = socket.connect(cx, remote, local) {
            drop(inner);
            self.release_tcp_port(local_port);
            return Err(Error::TcpConnectGeneric(format!(
                "TCP connect failed: {}",
                e
            )));
        }

        log::debug!("TCP socket connecting to {} from {}", addr, log_local);

        // 避免 unused：仅用于 SocketAddrV6 import 抑制
        let _ = std::marker::PhantomData::<SocketAddrV6>;

        Ok(local_port)
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
        {
            let mut inner = self.inner.lock();
            inner.sockets.remove(handle);
            inner.signals.remove(&handle);
        }
        // 与 create_*_socket 的 increment 配对，见 `warp_rust_netstack_sockets_active`。
        metrics::gauge!("warp_rust_netstack_sockets_active").decrement(1.0);
    }

    /// 当前 SocketSet 中的 socket 数量（TCP + UDP）。用于观测与泄漏回归测试：
    /// 稳态下应等于活跃连接数；若持续高于活跃连接数即为孤儿 socket 累积。
    pub fn socket_count(&self) -> usize {
        self.inner.lock().sockets.iter().count()
    }

    fn socket_signals(&self, handle: SocketHandle) -> Arc<SocketSignals> {
        self.inner
            .lock()
            .signals
            .get(&handle)
            .cloned()
            .expect("socket signals must exist while socket is registered")
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
                ref signals,
            } = *inner;

            let rx_queue_len = device.rx_queue.len();

            // Poll the interface
            let poll_result = interface.poll(timestamp, device, sockets);
            let processed = poll_result != PollResult::None;

            if processed {
                notify_ready_sockets(sockets, signals);
            }

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

        let accepted = {
            let mut inner = self.inner.lock();
            inner.device.push_rx(packet)
        };
        if !accepted {
            metrics::counter!("warp_rust_netstack_rx_queue_dropped_total").increment(1);
            log::debug!("netstack RX queue full; dropping packet");
        }
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
        loop {
            let sleep_dur = {
                let mut inner = self.inner.lock();
                // 必须与 `poll()` / Interface::new 使用同一时钟域。旧代码从本
                // poll loop 启动时重新以 0 计时，而 `poll()` 用 Instant::now()，
                // 导致 poll_at 计算出的 TCP 重传 deadline 被错误拉长到 1s 兜底。
                let now = Instant::now();
                let NetStackInner {
                    ref mut interface,
                    ref device,
                    ref sockets,
                    ..
                } = *inner;
                if device.has_pending_tx() {
                    Duration::from_millis(1)
                } else {
                    match interface.poll_at(now, sockets) {
                        Some(at) if at > now => {
                            // `at > now` 已经保证差值为正，无需再 max(0)。
                            let ms = (at - now).total_millis();
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
    local_port: u16,
    signals: Arc<SocketSignals>,
}

impl TcpConnection {
    /// Create a new TCP connection.
    ///
    /// 取消安全（warp-rust fork：修复「connect 中途失败/取消泄漏 2×tcp_buffer_size
    /// socket buffer」）：`create_tcp_socket()` 会**立即**把携带 rx+tx buffer 的
    /// socket 加入 `SocketSet`。在连接进入 `Established`、`Ok(Self)` 构造成功**之前**
    /// 的任何出口都会留下孤儿 socket：
    ///   - `netstack.connect(handle, addr)?` 提前返回 `Err`（如无 v6 隧道时的
    ///     `Ipv6NotSupported`，或 smoltcp 的 `InvalidState`/`Unaddressable`）；
    ///   - 循环里 `Closed`/`TimeWait`/30s 超时的 `Err` 返回；
    ///   - 等待 socket signal 时被上层取消——happy-eyeballs 败者 future 被
    ///     `select!` drop、健康探针 `timeout()` 到期 drop 等。
    ///
    /// `TcpConnection::Drop` 只在对象构造成功后才存在，救不了上述路径。
    ///
    /// 用一个栈上 RAII guard 兜底：未 disarm 时其 `Drop` 调 `remove_socket`。guard
    /// 是本 future 的局部变量，future 在任意 `.await` 点被 drop 时它必然运行，故对
    /// 所有取消点都安全。仅在返回 `Ok(Self)` 前 disarm，把 socket 所有权交还给
    /// `TcpConnection::Drop`。取消时 socket 处于 `SynSent`（本端 client + ephemeral
    /// 端口），直接 remove 即可，无需 close()+poll() 发 FIN（远端自行清理半开连接）。
    pub async fn connect(netstack: Arc<NetStack>, addr: SocketAddr) -> Result<Self> {
        // connect 成功前兜底回收 socket 的 RAII guard（见上方文档）。
        struct SocketGuard {
            netstack: Arc<NetStack>,
            handle: SocketHandle,
            local_port: Option<u16>,
            armed: bool,
        }
        impl Drop for SocketGuard {
            fn drop(&mut self) {
                if self.armed {
                    self.netstack.remove_socket(self.handle);
                    if let Some(port) = self.local_port {
                        self.netstack.release_tcp_port(port);
                    }
                }
            }
        }

        let handle = netstack.create_tcp_socket();
        let signals = netstack.socket_signals(handle);
        // guard 持一份 Arc clone（仅 refcount +1），与下面 `Self { netstack }` 的移动解耦。
        let mut guard = SocketGuard {
            netstack: Arc::clone(&netstack),
            handle,
            local_port: None,
            armed: true,
        };

        let local_port = netstack.connect(handle, addr)?; // Err → guard.drop → remove_socket
        guard.local_port = Some(local_port);
        // 立即叫 poll loop 把 SYN 发出去
        netstack.kick();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            // 先把 waiter 注册进 Notify 队列，再检查 socket 状态，消除
            // check→wait 之间的丢通知窗口；无需旧版每 1ms 忙轮询兜底。
            let notified = signals.connect.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let state = netstack.socket_state(handle);
            if state == TcpState::Established {
                guard.armed = false; // 交棒给 TcpConnection::Drop
                log::debug!("TCP connection established to {}", addr);
                return Ok(Self {
                    netstack: Arc::clone(&netstack),
                    handle,
                    local_port,
                    signals: Arc::clone(&signals),
                });
            }
            if state == TcpState::Closed || state == TcpState::TimeWait {
                // guard.drop → remove_socket
                return Err(Error::TcpConnect {
                    addr,
                    message: format!("Connection failed (state: {:?})", state),
                });
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::TcpTimeout); // guard.drop → remove_socket
            }
            tokio::select! {
                _ = notified.as_mut() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::TcpTimeout); // guard.drop → remove_socket
                }
            }
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
            let notified = self.signals.read.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (n, may_recv) = self.netstack.recv_with_state(self.handle, buf)?;
            if n > 0 {
                return Ok(n);
            }
            if !may_recv {
                return Ok(0); // 对端关闭
            }
            notified.await;
        }
    }

    /// Write data to the connection.
    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        let mut written = 0;

        // v0.3.1（Bug #5 (A)）：`send_with_state` 把 can_send + send +
        // may_send 合成单次取锁；写出非零字节后再叫一次 `kick()`（在锁外）
        // 让 poll loop 立即把包发出去。
        while written < data.len() {
            let notified = self.signals.write.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
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
            notified.await;
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
        self.netstack.release_tcp_port(self.local_port);
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
/// 单个 association 等待 smoltcp UDP TX buffer 腾出空间的总时限。
///
/// 正常 poll loop 会在一次事件循环内排空 socket；200ms 给突发流量足够的回压
/// 窗口，同时避免坏隧道让单个 SOCKS5 UDP association 无限卡住。
const UDP_SEND_WAIT_TIMEOUT: Duration = Duration::from_millis(200);
const IPV4_HEADER_BYTES: usize = 20;
const IPV6_HEADER_BYTES: usize = 40;
const UDP_HEADER_BYTES: usize = 8;
/// 一个需要分片的报文最多允许占用多少轮 `Interface::poll` 把分片推完。
///
/// 8164 字节的上限在 MTU 1280 下最多 7 片，一次 `poll()` 通常能吐 2 片，32 轮
/// 留了充足余量。真正跑满只可能是 device queue 被 WireGuard 侧长期打满。
const MAX_FRAGMENT_FLUSH_ROUNDS: usize = 32;

/// 把一个刚入队的、需要 IP 分片的报文的**全部**分片推进 device queue。
///
/// 必须在 `NetStackInner` 的同一个临界区内完成：smoltcp 的 `Fragmenter` 是每个
/// `Interface` **唯一一份**（`iface::fragmentation::Fragmenter`），而 `dispatch_ip`
/// 在开始一个新的分片序列时会无条件覆写 `packet_len / sent_bytes / buffer`，
/// 没有任何 in-flight 保护。一旦在分片途中释放锁，另一个大报文就能通过
/// `socket_egress` 抢先进入 `dispatch_ip` 并把前一个报文的剩余分片彻底冲掉——
/// 线路上只留下没有末片的半截数据，对端占着重组槽直到超时，而两次
/// `send_slice` 都返回了 `Ok(())`。
///
/// 收敛判据用「末片出现」（`more_frags == 0 && frag_offset > 0`）；这是精确的，
/// 不受其它 socket 的出站包干扰。`poll_at` 兜住「实际没触发分片」的边界情况：
/// 它在 fragmenter 非空时优先返回 `Instant::from_millis(0)`，所以只要它不再
/// 返回 0，fragmenter 一定是空的。
///
/// 降级行为：真的跑满 `MAX_FRAGMENT_FLUSH_ROUNDS`（意味着 device queue 被
/// WireGuard 出口长期打满）时返回错误让调用方计数并丢弃。此时已经吐出的前几片
/// 仍会随 poll loop 发出去，对端会因重组超时把它们丢掉——这里刻意不去
/// `truncate` tx_queue，因为那几轮 poll 里同时可能产生其它 socket 的正常报文，
/// 误删它们的代价比让对端超时更高。
fn flush_pending_fragments(
    interface: &mut Interface,
    device: &mut VirtualDevice,
    sockets: &mut SocketSet<'static>,
    signals: &HashMap<SocketHandle, Arc<SocketSignals>>,
) -> Result<()> {
    let start = device.tx_queue.len();
    for _ in 0..MAX_FRAGMENT_FLUSH_ROUNDS {
        let timestamp = Instant::now();
        if interface.poll(timestamp, device, sockets) != PollResult::None {
            // 这几轮 poll 也会消化 ingress；不在这里唤醒的话，poll loop 之后会
            // 拿到 PollResult::None 而跳过唤醒，读者被无谓地拖到下一次事件。
            notify_ready_sockets(sockets, signals);
        }

        let flushed = device.tx_queue.iter().skip(start).any(|bytes| {
            Ipv4Packet::new_checked(bytes.as_ref())
                .map(|packet| !packet.more_frags() && packet.frag_offset() > 0)
                .unwrap_or(false)
        });
        if flushed {
            return Ok(());
        }
        // 报文最终没有触发分片（例如长度恰好等于单片容量）时不会有末片，
        // 此时 fragmenter 本来就是空的，poll_at 会给出确定的收敛信号。
        if interface.poll_at(timestamp, sockets) != Some(Instant::from_millis(0)) {
            return Ok(());
        }
    }
    Err(Error::UdpFragmentFlush(MAX_FRAGMENT_FLUSH_ROUNDS))
}

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
        let (port, allocated_port) = if local_port == 0 {
            (self.allocate_udp_port()?, true)
        } else {
            (local_port, false)
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
        if let Err(e) = socket.bind(listen) {
            if allocated_port {
                self.release_udp_port(port);
            }
            return Err(Error::TcpConnectGeneric(format!("UDP bind failed: {}", e)));
        }

        // 锁内：仅做 slab 插入。
        let signals = Arc::new(SocketSignals::default());
        let handle = {
            let mut inner = self.inner.lock();
            let handle = inner.sockets.add(socket);
            inner.signals.insert(handle, signals.clone());
            handle
        };
        // 与 remove_socket 的 decrement 配对，见 `warp_rust_netstack_sockets_active`。
        metrics::gauge!("warp_rust_netstack_sockets_active").increment(1.0);
        log::debug!("UDP socket bound to {}:{}", log_str, port);

        Ok(UdpHandle {
            netstack: Arc::clone(self),
            handle,
            local_port: port,
            allocated_port,
            signals,
        })
    }

    /// 通过 `handle` 向 `dest` 发送一个 UDP 数据报。Ok 表示 smoltcp 已经接收
    /// 净荷；后续由 netstack 的 poll 循环把它真正发出去。
    /// v0.2.0：支持 v4 与 v6 目标。
    pub fn udp_send_to(
        &self,
        handle: SocketHandle,
        payload: &[u8],
        dest: SocketAddr,
    ) -> Result<()> {
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
        // smoltcp 只对 IPv4 做出站分片；判据与 `dispatch_ip` 里的
        // `total_ip_len > mtu` 保持一致。
        let needs_fragmentation = dest.is_ipv4()
            && payload.len() + IPV4_HEADER_BYTES + UDP_HEADER_BYTES > self.wg_tunnel.mtu() as usize;

        let mut inner = self.inner.lock();
        let NetStackInner {
            ref mut interface,
            ref mut device,
            ref mut sockets,
            ref signals,
        } = *inner;
        let socket = sockets.get_mut::<UdpSocket>(handle);
        match socket.send_slice(payload, endpoint) {
            Ok(()) => {}
            Err(UdpSendError::BufferFull) => return Err(Error::UdpSendBufferFull),
            Err(UdpSendError::Unaddressable) => {
                return Err(Error::UdpSend(format!("unaddressable destination {dest}")))
            }
        }

        if needs_fragmentation {
            flush_pending_fragments(interface, device, sockets, signals)?;
        }
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
            .map_err(|e| Error::UdpRecv(e.to_string()))?;
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
    allocated_port: bool,
    signals: Arc<SocketSignals>,
}

impl UdpHandle {
    /// 当前 socket 绑定在 tunnel 接口上的本地端口
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    fn max_payload_for(&self, dest: SocketAddr) -> usize {
        let mtu = self.netstack.wg_tunnel.mtu() as usize;
        match dest {
            // IPv4 可由 smoltcp 分片；显式受 8KiB fragmenter 限制，避免超限时
            // smoltcp 只写 debug 后静默返回 Ok。
            SocketAddr::V4(_) => smoltcp::config::FRAGMENTATION_BUFFER_SIZE
                .saturating_sub(IPV4_HEADER_BYTES + UDP_HEADER_BYTES),
            // smoltcp 0.13 不做 IPv6 出站分片，因此必须限制为一枚内层 IPv6 包。
            SocketAddr::V6(_) => mtu.saturating_sub(IPV6_HEADER_BYTES + UDP_HEADER_BYTES),
        }
    }

    /// 发送一个数据报。TX buffer 满时等待本 socket 的可写通知并有限重试；
    /// 只有总 deadline 到期才向调用方报告丢包。
    pub async fn send_to(&self, payload: &[u8], dest: SocketAddr) -> Result<()> {
        let max = self.max_payload_for(dest);
        if payload.len() > max {
            metrics::counter!(
                "warp_rust_udp_tx_dropped_total",
                "reason" => "packet_too_large"
            )
            .increment(1);
            return Err(Error::UdpPacketTooLarge {
                family: if dest.is_ipv4() { "ipv4" } else { "ipv6" },
                size: payload.len(),
                max,
            });
        }

        let deadline = tokio::time::Instant::now() + UDP_SEND_WAIT_TIMEOUT;
        let mut was_full = false;
        loop {
            // 先注册通知再检查状态，避免 poll loop 恰好在 BufferFull 判断和
            // await 之间腾出空间而产生 lost wakeup。
            let notified = self.signals.udp_write.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            match self.netstack.udp_send_to(self.handle, payload, dest) {
                Ok(()) => {
                    self.netstack.kick();
                    if was_full {
                        metrics::counter!("warp_rust_udp_tx_recovered_total").increment(1);
                    }
                    return Ok(());
                }
                Err(Error::UdpSendBufferFull) => {
                    // 每个**报文**只记一次，而不是每次重试都记：recovered 和
                    // dropped 都是按报文计数的，三者同量纲后
                    // `recovered / buffer_full` 才是可用的恢复率 SLI。
                    if !was_full {
                        was_full = true;
                        metrics::counter!("warp_rust_udp_tx_buffer_full_total").increment(1);
                    }
                    self.netstack.kick();
                }
                Err(e) => {
                    // 分片 flush 失败单独归因：它意味着 WireGuard 出口长期打满，
                    // 与「目标不可寻址」这类 send_error 是完全不同的运维信号。
                    let reason = if matches!(e, Error::UdpFragmentFlush(_)) {
                        "fragment_flush"
                    } else {
                        "send_error"
                    };
                    metrics::counter!("warp_rust_udp_tx_dropped_total", "reason" => reason)
                        .increment(1);
                    return Err(e);
                }
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                metrics::counter!(
                    "warp_rust_udp_tx_dropped_total",
                    "reason" => "buffer_timeout"
                )
                .increment(1);
                return Err(Error::UdpSendTimeout(UDP_SEND_WAIT_TIMEOUT));
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(deadline) => {
                    // 下一轮再尝试一次；若空间已经腾出则成功，否则按 deadline 丢弃。
                }
            }
        }
    }

    /// 接收一个数据报。最多等待 `timeout`；超时返回 `Err(ReadTimeout)`。
    /// v0.3.x：与 TCP read 对齐 —— 不再 1ms 忙轮询，也不在 hot path 主动
    /// `poll()`（会跟 poll loop 抢 inner 锁）。改成先 try_recv，无数据时挂
    /// 在本 UDP socket 的 signal 上等 poll loop 唤醒；用一个总 deadline 控制超时。
    /// v0.2.0：返回 SocketAddr（v4/v6）。
    pub async fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<(usize, SocketAddr)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.signals.udp_read.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(got) = self.netstack.udp_try_recv(self.handle, buf)? {
                return Ok(got);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(Error::ReadTimeout);
            }
            // 等到 poll loop 处理过该 socket 的 rx，或到 deadline 为止。
            tokio::select! {
                _ = &mut notified => {}
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
        if self.allocated_port {
            self.netstack.release_udp_port(self.local_port);
        }
        self.netstack.kick();
    }
}

#[cfg(test)]
mod connect_leak_tests {
    //! 回归测试：`TcpConnection::connect` 在「成功 Established 之前」的失败/取消
    //! 路径上必须把已分配的 socket 从 SocketSet 移除，否则每次泄漏
    //! `2 × tcp_buffer_size`。这些测试无需真实 WARP peer：只构造 tunnel + netstack
    //! （不跑后台 poll loop），让 connect 卡在 SynSent / 早退，再用 `socket_count()`
    //! 断言无残留。
    use super::*;
    use crate::wireguard::{WireGuardConfig, WireGuardTunnel};
    use smoltcp::wire::Ipv6Packet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    async fn test_netstack_and_tunnel(
        tunnel_ipv6: Option<Ipv6Addr>,
    ) -> (Arc<NetStack>, Arc<WireGuardTunnel>) {
        let config = WireGuardConfig {
            private_key: [7u8; 32],
            peer_public_key: [9u8; 32],
            peer_endpoint: "127.0.0.1:51820".parse().unwrap(),
            peer_endpoint_candidates: vec!["127.0.0.1:51820".parse().unwrap()],
            tunnel_ip: Ipv4Addr::new(10, 0, 0, 2),
            tunnel_ipv6,
            preshared_key: None,
            keepalive_seconds: None,
            mtu: Some(1280),
            tcp_buffer_size: Some(4096), // 测试用小 buffer
        };
        let wg = WireGuardTunnel::new(config)
            .await
            .expect("construct wg tunnel for test");
        (NetStack::new(wg.clone()), wg)
    }

    async fn test_netstack_with_v6(tunnel_ipv6: Option<Ipv6Addr>) -> Arc<NetStack> {
        test_netstack_and_tunnel(tunnel_ipv6).await.0
    }

    async fn test_netstack() -> Arc<NetStack> {
        test_netstack_with_v6(None).await
    }

    /// 路径 A：向无 v6 隧道拨 v6 目标 → `netstack.connect` 经 `?` 返回
    /// `Ipv6NotSupported`；guard 必须移除已 create 的 socket。
    #[tokio::test]
    async fn connect_ipv6_without_tunnel_v6_does_not_leak_socket() {
        let ns = test_netstack().await;
        assert_eq!(ns.socket_count(), 0);

        let v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        let r = TcpConnection::connect(ns.clone(), v6).await;
        assert!(r.is_err(), "v6 dial on v4-only tunnel must fail");
        assert_eq!(
            ns.socket_count(),
            0,
            "guard 必须在 `?` 早退路径(A)上移除 socket"
        );
    }

    /// 路径 B：connect future 在 `wait_for_activity().await` 处被取消（模拟
    /// happy-eyeballs 败者 / 探针 timeout 被 drop）→ guard 必须移除 socket。
    #[tokio::test]
    async fn connect_cancellation_does_not_leak_socket() {
        let ns = test_netstack().await;
        assert_eq!(ns.socket_count(), 0);

        let ns2 = ns.clone();
        let task = tokio::spawn(async move {
            // 无 peer + 无 poll loop → 永停在 SynSent，connect 卡在 wait_for_activity
            let v4: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let _ = TcpConnection::connect(ns2, v4).await;
        });

        // 给它时间分配 socket 并 park
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(ns.socket_count(), 1, "connect 进行中应已分配 socket");

        // 取消（drop future）→ guard.drop 必须 remove_socket
        task.abort();
        let _ = task.await;
        assert_eq!(ns.socket_count(), 0, "guard 必须在取消路径(B)上移除 socket");
    }

    /// 正常成功路径不受影响：guard disarm 后由 `TcpConnection::Drop` 接管，
    /// 且不会 double-remove（重复 remove 会 panic）。这里只能验证早退/取消，
    /// Established 需真实 peer，故用 UdpHandle 的对称路径间接覆盖 remove 计数正确。
    #[tokio::test]
    async fn udp_handle_drop_removes_socket() {
        let ns = test_netstack().await;
        assert_eq!(ns.socket_count(), 0);
        {
            let _udp = ns.create_udp_socket(0).expect("bind udp");
            assert_eq!(ns.socket_count(), 1);
        }
        assert_eq!(ns.socket_count(), 0, "UdpHandle::Drop 必须移除 socket");
    }

    #[tokio::test]
    async fn udp_payload_boundaries_are_explicit_for_ipv4_and_ipv6() {
        let (ns, wg) = test_netstack_and_tunnel(Some("fd00::2".parse().unwrap())).await;
        let v4 = ns.create_udp_socket(0).expect("bind v4 udp");
        let v6 = ns.create_udp_socket_with(0, true).expect("bind v6 udp");
        let dst_v4 = SocketAddr::new("1.1.1.1".parse().unwrap(), v4.local_port());
        let dst_v6: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();

        assert_eq!(v4.max_payload_for(dst_v4), 8192 - 20 - 8);
        assert_eq!(v6.max_payload_for(dst_v6), 1280 - 40 - 8);

        for size in [1232usize, 1252, 1500, 4096] {
            v4.send_to(&vec![0u8; size], dst_v4)
                .await
                .unwrap_or_else(|e| panic!("IPv4 payload {size} should be accepted: {e}"));
            // 推进 interface 并直接检查送入 WireGuard 的内层 IP 包：大包必须
            // 真正产出连续 fragments，而不是 send_to 返回成功后静默消失。
            for _ in 0..8 {
                ns.poll();
            }
            let mut emitted = Vec::new();
            while let Some(packet) = wg.try_take_outgoing_packet().await {
                emitted.push(packet);
            }
            assert!(!emitted.is_empty(), "IPv4 payload {size} was silently lost");
            assert_eq!(
                emitted.len() > 1,
                size > 1252,
                "unexpected fragmentation count for payload {size}: {}",
                emitted.len()
            );
            let mut next_offset = 0usize;
            for (index, bytes) in emitted.iter().enumerate() {
                let packet = Ipv4Packet::new_checked(bytes.as_ref()).expect("valid IPv4 fragment");
                assert_eq!(packet.frag_offset() as usize, next_offset);
                next_offset += packet.payload().len();
                assert_eq!(
                    packet.more_frags(),
                    index + 1 < emitted.len(),
                    "invalid more-fragments flag for payload {size}"
                );
            }
            assert_eq!(next_offset, size + UDP_HEADER_BYTES);

            // 把 fragments 的 IP 方向反转后喂回同一 netstack，验证重组后的
            // UDP payload 长度与内容完整。两端 UDP port 相同、IP 地址仅互换，
            // 因此原 UDP pseudo-header checksum 仍然有效。
            for bytes in &mut emitted {
                let mut packet =
                    Ipv4Packet::new_checked(bytes.as_mut()).expect("mutable IPv4 fragment");
                packet.set_src_addr(Ipv4Address::new(1, 1, 1, 1));
                packet.set_dst_addr(Ipv4Address::new(10, 0, 0, 2));
                packet.fill_checksum();
            }
            for bytes in emitted {
                ns.push_rx_packet(bytes);
            }
            for _ in 0..8 {
                ns.poll();
            }
            let mut received = vec![0xff; size + 32];
            let (received_len, source) = v4
                .recv_from(&mut received, Duration::from_millis(20))
                .await
                .unwrap_or_else(|e| panic!("IPv4 payload {size} did not reassemble: {e}"));
            assert_eq!(received_len, size);
            assert_eq!(source.ip(), dst_v4.ip());
            assert_eq!(&received[..received_len], vec![0u8; size]);
        }

        v6.send_to(&vec![0u8; 1232], dst_v6)
            .await
            .expect("IPv6 payload at MTU boundary should be accepted");
        ns.poll();
        let emitted_v6 = wg
            .try_take_outgoing_packet()
            .await
            .expect("IPv6 payload at MTU boundary must reach WireGuard");
        let emitted_v6 =
            Ipv6Packet::new_checked(emitted_v6.as_ref()).expect("valid emitted IPv6 packet");
        assert_eq!(emitted_v6.payload_len(), 1232 + UDP_HEADER_BYTES as u16);
        assert_eq!(emitted_v6.total_len(), 1280);
        assert!(wg.try_take_outgoing_packet().await.is_none());

        let err = v6
            .send_to(&vec![0u8; 1252], dst_v6)
            .await
            .expect_err("oversized IPv6 UDP must be rejected explicitly");
        assert!(matches!(
            err,
            Error::UdpPacketTooLarge {
                family: "ipv6",
                size: 1252,
                max: 1232
            }
        ));
    }

    #[tokio::test]
    async fn udp_buffer_full_waits_and_recovers_after_poll() {
        let ns = test_netstack().await;
        let udp = Arc::new(ns.create_udp_socket(0).expect("bind udp"));
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();

        // 不启动 poll loop，先占满 32 个 metadata slot。
        for _ in 0..UDP_PKT_SLOTS {
            udp.send_to(&[1u8], dst).await.expect("fill UDP TX queue");
        }

        let pending = {
            let udp = udp.clone();
            tokio::spawn(async move { udp.send_to(&[2u8], dst).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !pending.is_finished(),
            "full queue should apply backpressure"
        );

        ns.poll();
        pending
            .await
            .expect("send task join")
            .expect("send should recover after writable notification");
    }

    #[tokio::test]
    async fn udp_buffer_full_reports_udp_timeout_not_tcp_error() {
        let ns = test_netstack().await;
        let udp = ns.create_udp_socket(0).expect("bind udp");
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();

        for _ in 0..UDP_PKT_SLOTS {
            udp.send_to(&[1u8], dst).await.expect("fill UDP TX queue");
        }
        let err = udp
            .send_to(&[2u8], dst)
            .await
            .expect_err("queue without poll must time out");
        assert!(matches!(err, Error::UdpSendTimeout(d) if d == UDP_SEND_WAIT_TIMEOUT));
        assert!(!err.to_string().contains("TCP send failed"));
    }

    /// 把 WireGuard 侧收到的全部出站包按 IPv4 ident 聚合成
    /// `ident -> (payload 字节总数, 是否见到 more_frags=false 的末片)`。
    async fn collect_ipv4_datagrams(
        wg: &WireGuardTunnel,
    ) -> std::collections::BTreeMap<u16, (usize, bool)> {
        let mut out: std::collections::BTreeMap<u16, (usize, bool)> = Default::default();
        while let Some(bytes) = wg.try_take_outgoing_packet().await {
            let Ok(packet) = Ipv4Packet::new_checked(bytes.as_ref()) else {
                continue;
            };
            let entry = out.entry(packet.ident()).or_insert((0, false));
            entry.0 += packet.payload().len();
            if !packet.more_frags() {
                entry.1 = true;
            }
        }
        out
    }

    /// 回归（v0.4.5）：smoltcp 的 `Fragmenter` 是每个 `Interface` **唯一一份**，
    /// 且 `dispatch_ip` 在进入分片分支时无条件覆写 `packet_len / sent_bytes /
    /// buffer`，没有任何 in-flight 保护。只要第二个待分片报文在前一个报文的
    /// 分片还没吐完时进入 egress，前一个报文就会在线路上被永久截断——末片
    /// 永远不出现，对端占着重组槽直到超时，而 `send_to` 两次都返回 `Ok(())`。
    ///
    /// 这里同时覆盖两条触发路径：不同 socket 并发、以及同一个 socket 背靠背
    /// 连发。修复前两条都会失败。
    #[tokio::test]
    async fn concurrent_large_udp_datagrams_are_never_truncated() {
        const PAYLOAD: usize = 4096;
        let expected = PAYLOAD + UDP_HEADER_BYTES;
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();

        // 路径 A：两个不同的 UDP socket 各发一个需要分片的报文。
        {
            let (ns, wg) = test_netstack_and_tunnel(None).await;
            let a = ns.create_udp_socket(0).expect("bind udp a");
            let b = ns.create_udp_socket(0).expect("bind udp b");
            a.send_to(&vec![0xa1; PAYLOAD], dst).await.expect("send a");
            b.send_to(&vec![0xb2; PAYLOAD], dst).await.expect("send b");
            for _ in 0..64 {
                ns.poll();
            }
            let grouped = collect_ipv4_datagrams(&wg).await;
            assert_eq!(
                grouped.len(),
                2,
                "两个 datagram 应各有独立 ident: {grouped:?}"
            );
            for (ident, (bytes, saw_last)) in &grouped {
                assert_eq!(*bytes, expected, "ident={ident} 的分片被截断: {grouped:?}");
                assert!(saw_last, "ident={ident} 从未发出末片: {grouped:?}");
            }
        }

        // 路径 B：同一个 socket 背靠背连发两个需要分片的报文。
        {
            let (ns, wg) = test_netstack_and_tunnel(None).await;
            let udp = ns.create_udp_socket(0).expect("bind udp");
            udp.send_to(&vec![0xc3; PAYLOAD], dst)
                .await
                .expect("send first");
            udp.send_to(&vec![0xd4; PAYLOAD], dst)
                .await
                .expect("send second");
            for _ in 0..64 {
                ns.poll();
            }
            let grouped = collect_ipv4_datagrams(&wg).await;
            assert_eq!(
                grouped.len(),
                2,
                "背靠背的两个 datagram 应各有独立 ident: {grouped:?}"
            );
            for (ident, (bytes, saw_last)) in &grouped {
                assert_eq!(*bytes, expected, "ident={ident} 的分片被截断: {grouped:?}");
                assert!(saw_last, "ident={ident} 从未发出末片: {grouped:?}");
            }
        }
    }
}
#[test]
fn ephemeral_allocator_is_collision_free_and_reuses_released_ports() {
    let mut ports = EphemeralPortAllocator::new();
    let mut allocated = std::collections::HashSet::new();
    for _ in 0..EPHEMERAL_PORT_COUNT {
        let port = ports.allocate().expect("range should have a free port");
        assert!(
            allocated.insert(port),
            "allocator returned duplicate {port}"
        );
    }
    assert!(
        ports.allocate().is_none(),
        "full range must report exhaustion"
    );

    let released: Vec<_> = allocated.iter().copied().take(256).collect();
    for port in &released {
        ports.release(*port);
    }
    let mut reused = std::collections::HashSet::new();
    for _ in 0..released.len() {
        reused.insert(ports.allocate().expect("released port should be reusable"));
    }
    assert_eq!(reused.len(), released.len());
}
