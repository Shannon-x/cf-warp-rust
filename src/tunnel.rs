//! WireGuard 隧道句柄。内部持有 `ManagedTunnel`，对外暴露 `dial_tcp` /
//! `bind_udp`；通过 `ArcSwap` 支持热替换，supervisor 重建隧道时不需要把
//! 在飞的拨号请求全部锁住。

use crate::error::{Error, Result};
use crate::metrics::{M_ACTIVE_TUNNEL_GENERATIONS, M_TUNNEL_GENERATIONS_FORCED_RETIRE};
use arc_swap::ArcSwap;
use metrics::{counter, gauge};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
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
    lease: Arc<TunnelGeneration>,
}

impl TunnelTcpConnection {
    pub async fn read(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<usize, wireguard_netstack::Error> {
        tokio::select! {
            biased;
            _ = self.lease.retired.cancelled() => Err(wireguard_netstack::Error::ConnectionClosed),
            result = self.inner.read(buf) => result,
        }
    }

    pub async fn write_all(
        &self,
        data: &[u8],
    ) -> std::result::Result<(), wireguard_netstack::Error> {
        tokio::select! {
            biased;
            _ = self.lease.retired.cancelled() => Err(wireguard_netstack::Error::ConnectionClosed),
            result = self.inner.write_all(data) => result,
        }
    }

    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

/// 上游 UDP socket 租约，与 [`TunnelTcpConnection`] 相同地保活旧隧道。
pub struct TunnelUdpHandle {
    inner: NetstackUdpHandle,
    lease: Arc<TunnelGeneration>,
}

impl TunnelUdpHandle {
    pub async fn send_to(
        &self,
        payload: &[u8],
        dest: SocketAddr,
    ) -> std::result::Result<(), wireguard_netstack::Error> {
        tokio::select! {
            biased;
            _ = self.lease.retired.cancelled() => {
                counter!(
                    "warp_rust_udp_tx_dropped_total",
                    "reason" => "generation_retired"
                ).increment(1);
                Err(wireguard_netstack::Error::ConnectionClosed)
            },
            result = self.inner.send_to(payload, dest) => result,
        }
    }

    pub async fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> std::result::Result<(usize, SocketAddr), wireguard_netstack::Error> {
        tokio::select! {
            biased;
            _ = self.lease.retired.cancelled() => Err(wireguard_netstack::Error::ConnectionClosed),
            result = self.inner.recv_from(buf, timeout) => result,
        }
    }
}

const DEFAULT_TUNNEL_DRAIN_GRACE: Duration = Duration::from_secs(5 * 60);
/// **故障恢复**时旧代际的 drain 窗口，远短于正常刷新的 5 分钟。
///
/// 旧代际是因为被判定不健康才被替换的，挂在它上面的连接基本不可能自行恢复
/// （现场表现为一律拨号超时）。但它们在被 retire 之前会一直占着全局
/// `max_concurrent_connections` 名额，于是新请求被 `连接被拒绝：达到
/// max_concurrent_connections` 挡在门外——故障被硬生生延长整整 5 分钟。
/// 现场时间线里 07:11:39 重建、07:16:39 旧隧道才退休，正好是这个常量。
///
/// 15 秒足够让真正还在传输的连接收尾（它们本来也熬不过一个 12s 的拨号超时），
/// 又能迅速把名额还给新请求。
const DEFAULT_TUNNEL_RECOVERY_DRAIN_GRACE: Duration = Duration::from_secs(15);
const DEFAULT_TUNNEL_MAX_GENERATION_AGE: Duration = Duration::from_secs(26 * 60 * 60);
/// 无论绝对寿命怎么压缩，被替换的代际都至少保留这么长的 drain 窗口。
///
/// 一个正好活过 `max_age` 才被替换的代际同样承载着在途连接；把 drain 直接归零
/// 会让它们被硬切在半路（而 relay 会把这种切断翻译成对客户端的干净 FIN，看起来
/// 就像响应正常结束）。绝对寿命的作用是**压缩** drain 窗口，不是消灭它。
const MIN_TUNNEL_DRAIN_GRACE: Duration = Duration::from_secs(30);
static NEXT_GENERATION_ID: AtomicU64 = AtomicU64::new(1);

/// 替换隧道的原因。决定旧代际能 drain 多久——这两种情形对「旧隧道还有没有
/// 救」的判断完全相反，不能共用一个窗口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceReason {
    /// 周期性配置刷新。旧隧道大概率仍然可用，给足 drain 窗口让长连接自然结束。
    Refresh,
    /// 故障恢复。旧隧道已被判定不健康，继续占着连接名额只会挤掉新请求。
    Recovery,
}

#[derive(Clone, Copy)]
struct GenerationPolicy {
    drain_grace: Duration,
    recovery_drain_grace: Duration,
    max_age: Duration,
}

impl GenerationPolicy {
    fn grace_for(&self, reason: ReplaceReason) -> Duration {
        match reason {
            ReplaceReason::Refresh => self.drain_grace,
            ReplaceReason::Recovery => self.recovery_drain_grace,
        }
    }
}

impl Default for GenerationPolicy {
    fn default() -> Self {
        Self {
            drain_grace: DEFAULT_TUNNEL_DRAIN_GRACE,
            recovery_drain_grace: DEFAULT_TUNNEL_RECOVERY_DRAIN_GRACE,
            max_age: DEFAULT_TUNNEL_MAX_GENERATION_AGE,
        }
    }
}

/// 一个刚被替换掉的代际还能再存活多久。
///
/// 语义（注意不是「每个 generation 有 26 小时绝对寿命」——活跃代际不受任何
/// 定时器约束，只有**被替换后**才开始计时）：
/// - 起点是 `reason` 对应的 grace：正常刷新 5 分钟，故障恢复 15 秒；
/// - 代际已经很老时，用 `max_age - age` 压缩这个窗口，使总寿命收敛到
///   `created_at + max_age`；
/// - 但压缩有下限，绝不会退化成立即硬切。下限本身还要再 `min` 一次 grace，
///   这样故障恢复的 15 秒不会被 30 秒的下限反过来拉长。
fn retirement_delay(age: Duration, policy: GenerationPolicy, reason: ReplaceReason) -> Duration {
    let grace = policy.grace_for(reason);
    grace
        .min(policy.max_age.saturating_sub(age))
        .max(MIN_TUNNEL_DRAIN_GRACE.min(grace))
}

struct TunnelGeneration {
    id: u64,
    managed: ManagedTunnel,
    retired: CancellationToken,
    created_at: Instant,
}

impl TunnelGeneration {
    fn new(managed: ManagedTunnel) -> Self {
        let id = NEXT_GENERATION_ID.fetch_add(1, Ordering::Relaxed);
        gauge!(M_ACTIVE_TUNNEL_GENERATIONS).increment(1.0);
        Self {
            id,
            managed,
            retired: CancellationToken::new(),
            created_at: Instant::now(),
        }
    }

    fn schedule_retirement(self: &Arc<Self>, policy: GenerationPolicy, reason: ReplaceReason) {
        let delay = retirement_delay(self.created_at.elapsed(), policy, reason);
        let weak = Arc::downgrade(self);
        let id = self.id;
        if delay.is_zero() {
            self.force_retire();
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    tokio::time::sleep(delay).await;
                    // Weak 不会为了计时器保活旧 tunnel；只有仍有连接 lease 时才强退。
                    if let Some(generation) = weak.upgrade() {
                        warn!(
                            generation = id,
                            ?delay,
                            ?reason,
                            "retiring drained tunnel generation"
                        );
                        generation.force_retire();
                    }
                });
            }
            Err(_) => {
                // replace 正常只会在 Tokio runtime 内调用；防御性地避免无 runtime
                // 时把旧 generation 永久保留。
                self.force_retire();
            }
        }
    }

    fn force_retire(&self) {
        if !self.retired.is_cancelled() {
            self.retired.cancel();
            counter!(M_TUNNEL_GENERATIONS_FORCED_RETIRE).increment(1);
        }
    }
}

impl Drop for TunnelGeneration {
    fn drop(&mut self) {
        gauge!(M_ACTIVE_TUNNEL_GENERATIONS).decrement(1.0);
        debug!(generation = self.id, "tunnel generation dropped");
    }
}

pub struct Tunnel {
    /// 重建期间短暂为 `None`；此时拨号会返回 `TunnelNotReady`。
    inner: ArcSwap<Option<Arc<TunnelGeneration>>>,
    generation_policy: GenerationPolicy,
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

/// 展开为真正要尝试的 `(IP, port)` 列表。当前 active endpoint 永远排第一，
/// 然后按 DNS/API 候选顺序扩展；每个 IP 都尝试原端口和 WARP 备用端口。
fn endpoint_attempts(cfg: &WireGuardConfig) -> Vec<SocketAddr> {
    let mut bases = Vec::new();
    bases.push(cfg.peer_endpoint);
    for endpoint in &cfg.peer_endpoint_candidates {
        if !bases.contains(endpoint) {
            bases.push(*endpoint);
        }
    }

    let mut attempts = Vec::new();
    // 先让每个 IP 都有一次原端口机会，避免在一个坏 IP 上串行耗尽四个端口
    // 之后才切到下一枚 A/AAAA。
    for base in &bases {
        if !attempts.contains(base) {
            attempts.push(*base);
        }
    }
    for base in bases {
        for port in endpoint_ports(base.port()) {
            let candidate = SocketAddr::new(base.ip(), port);
            if !attempts.contains(&candidate) {
                attempts.push(candidate);
            }
        }
    }
    attempts
}

const MAX_PARALLEL_ENDPOINT_ATTEMPTS: usize = 2;

async fn try_endpoint(
    mut cfg: WireGuardConfig,
    endpoint: SocketAddr,
    timeout: Duration,
) -> (WireGuardConfig, wireguard_netstack::Result<ManagedTunnel>) {
    cfg.peer_endpoint = endpoint;
    let result = ManagedTunnel::connect_with_timeout(cfg.clone(), timeout).await;
    (cfg, result)
}

/// 从错误文案里回捞 `(os error N)` 里的 N。
///
/// 隧道构造失败在 vendored crate 里被逐层包成 `String`，结构化的 `io::Error`
/// 早已丢失，只能从 Display 里往回解析。但**errno 数字比文案稳健得多**：同一个
/// errno 在不同平台的文案并不一样，例如 EADDRNOTAVAIL 在 macOS 是
/// `"Can't assign requested address"`、在 Linux 是 `"Cannot assign requested
/// address"`，靠文案匹配必然漏掉一半平台。
fn os_errno(failure: &str) -> Option<i32> {
    const MARKER: &str = "(os error ";
    let start = failure.rfind(MARKER)? + MARKER.len();
    let rest = &failure[start..];
    rest[..rest.find(')')?].trim().parse().ok()
}

/// 「该地址族 / 路由在本机根本不可用」这一类失败，与本机防火墙无关。
///
/// v0.4.5 把 DNS 的全部 A/AAAA 和 API 的 v4/v6 都放进候选之后，纯 IPv4 的 VPS
/// 上必然会出现 IPv6 尝试失败（Docker 默认关 IPv6 → EAFNOSUPPORT；有模块但无
/// 全局路由 → ENETUNREACH；有默认路由但网关不可达 → EHOSTUNREACH）。如果把
/// 这些也算进 EPERM 判断，`all()` 永远是 false，v0.4.3 起就有的防火墙提示在真实
/// 环境里 100% 出不来——而单元测试只喂纯 IPv4 的 EPERM 字符串，所以测试还是全绿。
///
/// 注意这里**不能**顺手把 EACCES 也算进来：`ip route add prohibit` 给的正是
/// EACCES，那是需要用户干预的策略性拒绝，应当留在判据里。
fn is_address_family_unavailable(failure: &str) -> bool {
    use std::io::ErrorKind;
    // 首选 errno→ErrorKind：它跟着当前平台走，未来新增的 errno 映射也能自动吃到。
    if let Some(errno) = os_errno(failure) {
        if matches!(
            std::io::Error::from_raw_os_error(errno).kind(),
            ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkDown
                | ErrorKind::AddrNotAvailable
        ) {
            return true;
        }
    }
    // 文案兜底，两个原因缺一不可：
    // 1. errno **数值是平台相关的**——`from_raw_os_error(97)` 在 Linux 上是
    //    EAFNOSUPPORT，在 macOS 上却是 ENOLINK。上面那步只在「文案和二进制来自
    //    同一平台」时准确，跨平台的日志/固定字符串会落空。
    // 2. EAFNOSUPPORT / EPFNOSUPPORT 在任何平台都没有专属 ErrorKind（都落到
    //    Uncategorized），只能按文案。
    // 因此这里把 Linux 与 macOS 两套 Display 文案都列全。
    const UNAVAILABLE_TEXTS: [&str; 6] = [
        // EAFNOSUPPORT / EPFNOSUPPORT：
        // "Address family not supported by protocol[ family]" / "Protocol family not supported"
        "family not supported",
        "Network is unreachable",          // ENETUNREACH
        "No route to host",                // EHOSTUNREACH
        "Network is down",                 // ENETDOWN
        "Cannot assign requested address", // EADDRNOTAVAIL (Linux)
        "Can't assign requested address",  // EADDRNOTAVAIL (macOS)
    ];
    UNAVAILABLE_TEXTS.iter().any(|text| failure.contains(text))
}

/// 当所有**与防火墙相关**的 endpoint 尝试都是 EPERM（内核对 sendto 返回
/// "Operation not permitted"）时，返回一条本机防火墙放行提示；否则返回空串。
///
/// 关键：用精确 Display 文案 `"Operation not permitted"` 判断，而不是
/// `contains("os error 1")`——后者会把 `os error 10/13/101/111`（网络不可达 /
/// 权限拒绝 / 连接拒绝等）误判成 EPERM。提示里只列**实际被 EPERM 拒绝**的
/// 那些 IP，避免把一长串无关候选塞进 iptables 建议里。
fn firewall_hint(failures: &[(SocketAddr, String)]) -> String {
    let relevant: Vec<&(SocketAddr, String)> = failures
        .iter()
        .filter(|(_, message)| !is_address_family_unavailable(message))
        .collect();
    if relevant.is_empty()
        || !relevant
            .iter()
            .all(|(_, message)| message.contains("Operation not permitted"))
    {
        return String::new();
    }

    let mut blocked_ips: Vec<IpAddr> = Vec::new();
    for (endpoint, _) in &relevant {
        if !blocked_ips.contains(&endpoint.ip()) {
            blocked_ips.push(endpoint.ip());
        }
    }
    let peers = blocked_ips
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let rules = blocked_ips
        .iter()
        .map(|ip| {
            let tool = if ip.is_ipv4() {
                "iptables"
            } else {
                "ip6tables"
            };
            format!("{tool} -A OUTPUT -p udp -d {ip} -j ACCEPT")
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        " —— 所有可判定的尝试都是 EPERM，通常是本机防火墙(iptables/nftables OUTPUT)拦截了\
         到 WARP endpoint [{peers}] 的出站 UDP。请放行到这些地址的\
         2408/500/1701/4500（例：`{rules}`）"
    )
}

impl Tunnel {
    /// 用一个已经建联完成的 `ManagedTunnel` 构造。
    pub fn from_managed(t: ManagedTunnel) -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::new(Arc::new(Some(Arc::new(TunnelGeneration::new(t))))),
            generation_policy: GenerationPolicy::default(),
        })
    }

    /// 重新建联，并原子地替换掉原来的隧道。旧隧道的后台任务会随 Drop 被 abort。
    ///
    /// `reason` 决定旧代际的 drain 窗口：故障恢复时旧隧道已经不可用，必须尽快
    /// 把它占用的连接名额还回来，不能按正常刷新那样 drain 5 分钟。
    pub async fn rebuild(
        &self,
        cfg: WireGuardConfig,
        reason: ReplaceReason,
    ) -> Result<WireGuardConfig> {
        info!(?reason, "rebuilding WireGuard tunnel");
        let connected = Self::connect_candidate(cfg).await?;
        let active_config = connected.config.clone();
        self.replace(connected.managed, reason);
        Ok(active_config)
    }

    /// 建立且完成握手的候选隧道，但不改动当前流量。按 DNS/API 返回的 IP 顺序，
    /// 对每个 IP 尝试原端口及 WARP 备用端口。每次失败的 ManagedTunnel 都会
    /// 立即 drop 并 abort 自己的后台任务。
    pub async fn connect_candidate(cfg: WireGuardConfig) -> Result<ConnectedTunnel> {
        let attempts = endpoint_attempts(&cfg);
        let original = cfg.peer_endpoint;
        let mut pending = attempts.into_iter().enumerate();
        let mut probes = tokio::task::JoinSet::new();
        let spawn_next =
            |probes: &mut tokio::task::JoinSet<_>,
             pending: &mut std::iter::Enumerate<std::vec::IntoIter<SocketAddr>>| {
                if let Some((index, endpoint)) = pending.next() {
                    let timeout = if index == 0 {
                        Duration::from_secs(10)
                    } else {
                        Duration::from_secs(5)
                    };
                    probes.spawn(try_endpoint(cfg.clone(), endpoint, timeout));
                    true
                } else {
                    false
                }
            };
        for _ in 0..MAX_PARALLEL_ENDPOINT_ATTEMPTS {
            if !spawn_next(&mut probes, &mut pending) {
                break;
            }
        }

        let mut failures = Vec::new();
        while let Some(joined) = probes.join_next().await {
            // 每完成一个就补一个，始终最多两路握手，避免注册同一 keypair 时的
            // 无界并发，同时让不同 IP 尽早参与竞争。
            let _ = spawn_next(&mut probes, &mut pending);
            match joined {
                Ok((candidate, Ok(managed))) => {
                    let endpoint = candidate.peer_endpoint;
                    probes.shutdown().await;
                    if endpoint != original {
                        warn!(
                            original = %original,
                            active = %endpoint,
                            "WireGuard connected through fallback endpoint"
                        );
                    }
                    return Ok(ConnectedTunnel {
                        managed,
                        config: candidate,
                    });
                }
                Ok((candidate, Err(e))) => {
                    let endpoint = candidate.peer_endpoint;
                    failures.push((endpoint, e.to_string()));
                    warn!(
                        peer = %endpoint,
                        error = %e,
                        "WireGuard endpoint attempt failed"
                    );
                }
                // JoinError 没有对应的 endpoint；用 UNSPECIFIED:0 占位，并让它
                // 落进 firewall_hint 的「非 EPERM」分支从而抑制误报提示。
                Err(e) => failures.push((
                    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                    format!("endpoint probe task failed: {e}"),
                )),
            }
        }

        let detail = failures
            .iter()
            .map(|(endpoint, message)| format!("{endpoint}: {message}"))
            .collect::<Vec<_>>()
            .join("; ");
        Err(Error::other(format!(
            "all WARP WireGuard endpoint candidates failed: {detail}{}",
            firewall_hint(&failures)
        )))
    }

    /// 候选隧道和账号都已验证/持久化后，做最后的原子切换。
    pub fn replace(&self, new: ManagedTunnel, reason: ReplaceReason) {
        let new = Arc::new(TunnelGeneration::new(new));
        let old = self.inner.swap(Arc::new(Some(new)));
        if let Some(old) = old.as_ref() {
            old.schedule_retirement(self.generation_policy, reason);
            debug!(
                generation = old.id,
                ?reason,
                grace = ?self.generation_policy.grace_for(reason),
                max_age = ?self.generation_policy.max_age,
                "previous tunnel generation draining"
            );
        }
    }

    /// 距上次成功的 WireGuard 握手过了多久；从未握手成功时为 `None`。
    ///
    /// 活跃会话每 ~120s 会重新握手，所以这个值显著超过 120s 就说明会话已经
    /// 陈旧——此时拨号必然失败，健康探针不必再干等一个完整的 8s 超时。
    /// 这个能力 vendored crate 一直提供，但在 v0.4.5 之前 `src/` 里零调用。
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let snapshot = self.inner.load_full();
        snapshot
            .as_ref()
            .as_ref()
            .and_then(|generation| generation.managed.time_since_last_handshake())
    }

    /// 取当前代际的快照。已经被退休的代际视同「隧道未就绪」。
    ///
    /// `load_full()` 与 swap 之间存在天然的快照竞态，而 `dial_tcp` 的 connect 还
    /// 会 await 数秒——期间代际可能被 `clear()` 或零延迟退休分支同步 cancel 掉。
    /// 如果不查这一下，调用方会拿到一个 lease 已失效的连接：SOCKS5 先回成功应答，
    /// 客户端紧接着读到 0 字节干净关闭，看起来就像「服务器返回了空响应」。
    fn live_generation(&self) -> Result<Arc<TunnelGeneration>> {
        let snapshot = self.inner.load_full();
        let generation = match snapshot.as_ref() {
            Some(t) => t.clone(),
            None => return Err(Error::TunnelNotReady),
        };
        if generation.retired.is_cancelled() {
            return Err(Error::TunnelNotReady);
        }
        Ok(generation)
    }

    /// 通过隧道拨号一个 TCP 目标。处于重建窗口期时返回 `TunnelNotReady`，
    /// SOCKS5 客户端通常会自动重试。
    pub async fn dial_tcp(&self, addr: SocketAddr) -> Result<TunnelTcpConnection> {
        // 从 Option 里 clone 出内层的 `Arc<TunnelGeneration>` —— 这样既不阻塞下
        // 一次 swap，也保证当前这条连接的整个生命周期里底层隧道不会被释放。
        let generation = self.live_generation()?;

        let inner = NetstackTcpConnection::connect(generation.managed.netstack(), addr)
            .await
            .map_err(|e| Error::Dial {
                addr,
                source: Box::new(e),
            })?;
        // connect 期间可能过去好几秒，出来后再确认一次代际仍然有效，避免把一条
        // 注定立刻被切断的连接交给客户端。
        if generation.retired.is_cancelled() {
            return Err(Error::TunnelNotReady);
        }
        Ok(TunnelTcpConnection {
            inner,
            lease: generation,
        })
    }

    /// 在隧道 netstack 内分配一个用户态 IPv4 UDP socket（ephemeral 端口）。
    pub fn bind_udp(&self) -> Result<TunnelUdpHandle> {
        let generation = self.live_generation()?;
        let inner = generation.managed.netstack().create_udp_socket(0)?;
        Ok(TunnelUdpHandle {
            inner,
            lease: generation,
        })
    }

    /// v0.2.2：在隧道 netstack 内分配一个用户态 IPv6 UDP socket。
    /// 如果 WARP 未提供 IPv6 tunnel 地址（即非双栈），返回 `Ok(None)`。
    pub fn bind_udp_v6(&self) -> Result<Option<TunnelUdpHandle>> {
        let generation = self.live_generation()?;
        if generation.managed.wg_tunnel().tunnel_ipv6().is_none() {
            return Ok(None);
        }
        let inner = generation
            .managed
            .netstack()
            .create_udp_socket_with(0, true)?;
        Ok(Some(TunnelUdpHandle {
            inner,
            lease: generation,
        }))
    }

    /// 释放内部隧道（主要供优雅停机调用）。
    pub fn clear(&self) {
        let old = self.inner.swap(Arc::new(None));
        if let Some(old) = old.as_ref() {
            old.force_retire();
        }
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
            .map(|t| t.managed.wg_tunnel().tunnel_ipv6().is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn endpoint_fallback_keeps_api_port_first_without_duplicates() {
        assert_eq!(endpoint_ports(2408), vec![2408, 500, 1701, 4500]);
        assert_eq!(endpoint_ports(500), vec![500, 2408, 1701, 4500]);
        assert_eq!(endpoint_ports(12345), vec![12345, 2408, 500, 1701, 4500]);
    }

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(162, 159, 192, 1))
    }

    fn config_with_candidates() -> WireGuardConfig {
        WireGuardConfig {
            private_key: [1u8; 32],
            peer_public_key: [2u8; 32],
            peer_endpoint: "162.159.192.1:2408".parse().unwrap(),
            peer_endpoint_candidates: vec![
                "162.159.192.1:2408".parse().unwrap(),
                "162.159.193.1:500".parse().unwrap(),
                "[2606:4700::1]:2408".parse().unwrap(),
            ],
            tunnel_ip: Ipv4Addr::new(172, 16, 0, 2),
            tunnel_ipv6: None,
            preshared_key: None,
            keepalive_seconds: Some(25),
            mtu: Some(1280),
            tcp_buffer_size: Some(4096),
        }
    }

    #[test]
    fn endpoint_attempts_cover_all_ips_and_ports_without_duplicates() {
        let attempts = endpoint_attempts(&config_with_candidates());
        assert_eq!(attempts[0], "162.159.192.1:2408".parse().unwrap());
        for ip in ["162.159.192.1", "162.159.193.1", "2606:4700::1"] {
            for port in [2408, 500, 1701, 4500] {
                let endpoint: SocketAddr = if ip.contains(':') {
                    format!("[{ip}]:{port}").parse().unwrap()
                } else {
                    format!("{ip}:{port}").parse().unwrap()
                };
                assert!(attempts.contains(&endpoint), "missing {endpoint}");
            }
        }
        let unique: std::collections::HashSet<_> = attempts.iter().collect();
        assert_eq!(unique.len(), attempts.len());
    }

    #[test]
    fn retired_generation_uses_drain_and_absolute_deadlines() {
        let policy = GenerationPolicy {
            drain_grace: Duration::from_secs(300),
            recovery_drain_grace: DEFAULT_TUNNEL_RECOVERY_DRAIN_GRACE,
            max_age: Duration::from_secs(26 * 60 * 60),
        };
        // 常态：完整的 drain 窗口。
        assert_eq!(
            retirement_delay(Duration::ZERO, policy, ReplaceReason::Refresh),
            Duration::from_secs(300)
        );
        // 接近绝对寿命：窗口被压缩，总寿命收敛到 created_at + max_age。
        assert_eq!(
            retirement_delay(
                Duration::from_secs(26 * 60 * 60 - 120),
                policy,
                ReplaceReason::Refresh
            ),
            Duration::from_secs(120)
        );
    }

    /// 回归（v0.4.5）：绝对寿命只能**压缩** drain 窗口，不能把它归零。
    ///
    /// 旧实现是裸的 `min(drain_grace, max_age - age)`，代际活过 max_age 才被
    /// replace 时 delay 变成 0 → 立刻 `force_retire()` → 所有在途 TCP/UDP 被
    /// 硬切，而 relay 会把它翻译成对客户端的干净 FIN（流式下载静默截断）。
    /// 默认 refresh_interval 是 24h，一旦刷新被推迟就会真实落到这个分支。
    #[test]
    fn retirement_delay_never_collapses_to_immediate_hard_cut() {
        let policy = GenerationPolicy {
            drain_grace: Duration::from_secs(300),
            recovery_drain_grace: DEFAULT_TUNNEL_RECOVERY_DRAIN_GRACE,
            max_age: Duration::from_secs(26 * 60 * 60),
        };
        for age_hours in [26, 27, 48, 240] {
            let delay = retirement_delay(
                Duration::from_secs(age_hours * 60 * 60),
                policy,
                ReplaceReason::Refresh,
            );
            assert_eq!(
                delay, MIN_TUNNEL_DRAIN_GRACE,
                "age={age_hours}h 时 drain 窗口不应归零"
            );
        }
        // 刚好卡在下限附近也不能低于 MIN。
        assert_eq!(
            retirement_delay(
                Duration::from_secs(26 * 60 * 60 - 5),
                policy,
                ReplaceReason::Refresh
            ),
            MIN_TUNNEL_DRAIN_GRACE
        );
    }

    /// 回归（v0.4.6）：故障恢复时旧代际必须**很快**退休，不能按正常刷新那样
    /// drain 5 分钟。
    ///
    /// 现场时间线：07:11:39 判定故障并重建隧道，07:16:39 旧隧道才退休——正好
    /// 5 分钟。这期间旧代际上那些已经拨号超时、永远不会恢复的连接一直占着全局
    /// `max_concurrent_connections` 名额，新请求被「连接被拒绝：达到
    /// max_concurrent_connections」挡在门外，故障因此被硬生生延长了 5 分钟。
    #[test]
    fn recovery_retires_the_old_generation_far_sooner_than_refresh() {
        let policy = GenerationPolicy::default();

        let refresh = retirement_delay(Duration::ZERO, policy, ReplaceReason::Refresh);
        let recovery = retirement_delay(Duration::ZERO, policy, ReplaceReason::Recovery);

        assert_eq!(
            refresh, DEFAULT_TUNNEL_DRAIN_GRACE,
            "正常刷新保持完整 drain"
        );
        assert_eq!(recovery, DEFAULT_TUNNEL_RECOVERY_DRAIN_GRACE);
        assert!(
            recovery < refresh,
            "故障恢复的 drain 窗口必须显著短于正常刷新: {recovery:?} vs {refresh:?}"
        );
        // 现场那 5 分钟的占用是问题的核心，退休必须在一个数量级以内完成。
        assert!(
            recovery <= Duration::from_secs(30),
            "恢复期 drain 不应超过 30s，实际 {recovery:?}"
        );
    }

    /// 30 秒的通用下限不能反过来把 15 秒的恢复窗口拉长——那会让上面那条修复
    /// 失效一半。
    #[test]
    fn recovery_grace_is_not_inflated_by_the_generic_floor() {
        let policy = GenerationPolicy::default();
        assert!(
            DEFAULT_TUNNEL_RECOVERY_DRAIN_GRACE < MIN_TUNNEL_DRAIN_GRACE,
            "这条测试的前提是恢复窗口比通用下限还短"
        );
        for age_hours in [0, 1, 26, 48] {
            let delay = retirement_delay(
                Duration::from_secs(age_hours * 60 * 60),
                policy,
                ReplaceReason::Recovery,
            );
            assert_eq!(
                delay, DEFAULT_TUNNEL_RECOVERY_DRAIN_GRACE,
                "age={age_hours}h 时恢复窗口被改变了"
            );
        }
    }

    /// 恢复窗口同样不能归零——旧代际上可能还有正在正常传输的连接，硬切会被
    /// relay 翻译成对客户端的干净 FIN，表现为响应静默截断。
    #[test]
    fn recovery_grace_still_never_reaches_zero() {
        let policy = GenerationPolicy::default();
        for age_hours in [26, 27, 240] {
            let delay = retirement_delay(
                Duration::from_secs(age_hours * 60 * 60),
                policy,
                ReplaceReason::Recovery,
            );
            assert!(!delay.is_zero(), "age={age_hours}h 时恢复窗口归零了");
        }
    }

    /// policy 本身把 drain_grace 配得比下限还短时，下限不应该反过来把它拉长。
    #[test]
    fn retirement_delay_respects_a_shorter_configured_grace() {
        let policy = GenerationPolicy {
            drain_grace: Duration::from_secs(5),
            recovery_drain_grace: Duration::from_secs(5),
            max_age: Duration::from_secs(60),
        };
        assert_eq!(
            retirement_delay(Duration::ZERO, policy, ReplaceReason::Refresh),
            Duration::from_secs(5)
        );
        assert_eq!(
            retirement_delay(Duration::from_secs(600), policy, ReplaceReason::Refresh),
            Duration::from_secs(5)
        );
    }

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(ip(), port)
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new("2606:4700::1".parse().unwrap(), port)
    }

    const EPERM: &str =
        "Failed to create WireGuard tunnel: IO error: Operation not permitted (os error 1)";

    #[test]
    fn firewall_hint_all_eperm_mentions_real_ip() {
        let f = vec![(v4(2408), EPERM.to_string()), (v4(500), EPERM.to_string())];
        let h = firewall_hint(&f);
        assert!(h.contains("162.159.192.1"), "应嵌入真实 peer IP: {h}");
        assert!(h.contains("iptables"));
    }

    /// 回归（v0.4.5）：候选里必然混入 IPv6，而纯 v4 的 VPS 上 IPv6 尝试会返回
    /// EAFNOSUPPORT / ENETUNREACH。这些与本机防火墙无关，不能让它们把 IPv4 上
    /// 真实存在的 EPERM 信号淹掉——否则这条可操作提示在生产环境永远出不来。
    #[test]
    fn firewall_hint_survives_unreachable_ipv6_candidates() {
        let f = vec![
            (v4(2408), EPERM.to_string()),
            (v4(500), EPERM.to_string()),
            (
                v6(2408),
                "Failed to create WireGuard tunnel: IO error: Address family not supported by protocol (os error 97)"
                    .to_string(),
            ),
            (
                v6(500),
                "Failed to create WireGuard tunnel: IO error: Network is unreachable (os error 101)"
                    .to_string(),
            ),
        ];
        let h = firewall_hint(&f);
        assert!(h.contains("162.159.192.1"), "IPv4 的 EPERM 信号应保留: {h}");
        assert!(
            !h.contains("2606:4700::1"),
            "不该把不可达的 v6 候选写进 iptables 建议: {h}"
        );
    }

    /// 回归：判据必须按 **errno** 而不是 Display 文案。同一个 errno 在不同平台
    /// 文案不同（EADDRNOTAVAIL 在 macOS 是 "Can't ..."、Linux 是 "Cannot ..."），
    /// 只匹配 Linux 文案会让整条防火墙提示在 macOS 上失效——而项目有
    /// release-macos.yml，macOS 是正式发布目标。
    /// 两个平台上「地址族/路由不可用」的真实 Display 文案。errno 数值是平台
    /// 相关的（97 在 Linux 是 EAFNOSUPPORT、在 macOS 是 ENOLINK），所以这里钉的是
    /// **文案**——判据必须与二进制跑在哪个平台无关。
    const UNAVAILABLE_MESSAGES: [(&str, &str); 11] = [
        (
            "Address family not supported by protocol (os error 97)",
            "linux EAFNOSUPPORT",
        ),
        ("Network is unreachable (os error 101)", "linux ENETUNREACH"),
        (
            "Cannot assign requested address (os error 99)",
            "linux EADDRNOTAVAIL",
        ),
        ("No route to host (os error 113)", "linux EHOSTUNREACH"),
        ("Network is down (os error 100)", "linux ENETDOWN"),
        (
            "Protocol family not supported (os error 96)",
            "linux EPFNOSUPPORT",
        ),
        (
            "Address family not supported by protocol family (os error 47)",
            "macos EAFNOSUPPORT",
        ),
        (
            "Can't assign requested address (os error 49)",
            "macos EADDRNOTAVAIL",
        ),
        ("No route to host (os error 65)", "macos EHOSTUNREACH"),
        ("Network is down (os error 50)", "macos ENETDOWN"),
        (
            "Protocol family not supported (os error 46)",
            "macos EPFNOSUPPORT",
        ),
    ];

    #[test]
    fn address_family_unavailable_covers_both_platforms() {
        for (rendered, label) in UNAVAILABLE_MESSAGES {
            let message = format!("Failed to create WireGuard tunnel: IO error: {rendered}");
            assert!(
                is_address_family_unavailable(&message),
                "{label} 应被判为地址族/路由不可用: {rendered}"
            );
        }

        // 反向：这些必须留在判据里，不能被当成「地址族不可用」剔除。
        // EACCES 尤其重要——`ip route add prohibit` 给的就是它，属于需要用户
        // 干预的策略性拒绝。
        for (rendered, label) in [
            ("Operation not permitted (os error 1)", "EPERM"),
            ("Permission denied (os error 13)", "EACCES"),
            ("Connection refused (os error 111)", "ECONNREFUSED"),
            ("WireGuard handshake timeout", "无 errno 的超时"),
        ] {
            let message = format!("Failed to create WireGuard tunnel: IO error: {rendered}");
            assert!(
                !is_address_family_unavailable(&message),
                "{label} 不该被剔除: {rendered}"
            );
        }
    }

    /// errno→ErrorKind 这条路径在**当前平台**上必须真的生效，而不是全靠文案兜底。
    #[test]
    fn address_family_unavailable_uses_errno_on_the_host_platform() {
        // ENETUNREACH 的当前平台 errno：Linux 101 / macOS 51。
        let errno = if cfg!(target_os = "macos") { 51 } else { 101 };
        let rendered = std::io::Error::from_raw_os_error(errno).to_string();
        assert_eq!(
            std::io::Error::from_raw_os_error(errno).kind(),
            std::io::ErrorKind::NetworkUnreachable,
            "当前平台 errno {errno} 应映射为 NetworkUnreachable: {rendered}"
        );
        assert!(is_address_family_unavailable(&format!(
            "IO error: {rendered}"
        )));
    }

    /// 端到端确认这些失败不会否决 IPv4 上真实的 EPERM 信号。
    #[test]
    fn firewall_hint_survives_every_unavailable_message() {
        for (rendered, label) in UNAVAILABLE_MESSAGES {
            let failures = vec![
                (v4(2408), EPERM.to_string()),
                (v4(500), EPERM.to_string()),
                (
                    v6(2408),
                    format!("Failed to create WireGuard tunnel: IO error: {rendered}"),
                ),
            ];
            let hint = firewall_hint(&failures);
            assert!(
                hint.contains("162.159.192.1"),
                "{label} 不应吞掉 IPv4 的 EPERM 提示: {rendered}"
            );
            assert!(
                !hint.contains("2606:4700::1"),
                "{label} 的 v6 候选不该进 iptables 建议: {hint}"
            );
        }
    }

    #[test]
    fn os_errno_parses_trailing_marker_only() {
        assert_eq!(
            os_errno("IO error: Operation not permitted (os error 1)"),
            Some(1)
        );
        assert_eq!(os_errno("no errno here"), None);
        // 嵌套文案取最后一个 marker，即最内层那个真正的 errno。
        assert_eq!(
            os_errno("outer (os error 5): inner failed (os error 101)"),
            Some(101)
        );
    }

    /// 只有 v6 不可达、没有任何可判定的失败时，不应该凭空断言是防火墙。
    #[test]
    fn firewall_hint_blank_when_only_family_unavailable() {
        let f = vec![(
            v6(2408),
            "IO error: Address family not supported by protocol (os error 97)".to_string(),
        )];
        assert!(firewall_hint(&f).is_empty());
    }

    /// 回归：`contains("os error 1")` 曾把 os error 10/13/101/111 误判成 EPERM。
    #[test]
    fn firewall_hint_not_triggered_by_other_errnos() {
        for s in [
            "Connection refused (os error 111)",
            "Permission denied (os error 13)",
            "WireGuard handshake timeout",
        ] {
            assert!(
                firewall_hint(&[(v4(2408), s.to_string())]).is_empty(),
                "不应对该错误给出防火墙提示: {s}"
            );
        }
    }

    #[test]
    fn firewall_hint_mixed_or_empty_is_blank() {
        // 混合（一个 EPERM 一个超时）→ 不下结论
        let mixed = vec![
            (v4(2408), "Operation not permitted (os error 1)".to_string()),
            (v4(500), "handshake timeout".to_string()),
        ];
        assert!(firewall_hint(&mixed).is_empty());
        assert!(firewall_hint(&[]).is_empty());
    }
}
