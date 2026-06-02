//! DNS 解析层。统一服务 SOCKS5 CONNECT（Domain ATYP）与 UDP ASSOCIATE。
//!
//! v0.2.1 起：
//! - 双栈解析：并发查 A 和 AAAA 记录，返回 v6 优先的 SocketAddr 列表
//! - 缓存按 (host, type) 分槽，v4/v6 独立 TTL
//! - 兼容旧 API：`resolve_v4` 保留作为快速 v4-only 通道（DNS、单栈调用）
//!
//! 两种 mode：
//! - `System`：走宿主 `tokio::net::lookup_host`（默认）；省心但 DNS 报文泄漏
//! - `Tunnel`：隧道内 UDP 拨 `[1.1.1.1:53, 1.0.0.1:53]`，手写 DNS wire format

use crate::config::{DnsConfig, DnsMode};
use crate::error::{Error, Result};
use crate::metrics::{
    M_DNS_CACHE_HIT, M_DNS_NEGATIVE_CACHE_HIT, M_DNS_QUERY, M_DNS_QUERY_FAIL,
    M_DNS_SINGLEFLIGHT_DEDUP,
};
use crate::tunnel::Tunnel;
use metrics::counter;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tokio::sync::Notify;
use tracing::{debug, trace, warn};

/// 缓存项：单条记录类型的解析结果。
///
/// `ip = None` 代表 negative cache：上一次查询失败（NXDOMAIN / no record /
/// 网络错误），在 `expires` 之前直接返回 Err，不再打 DNS。
#[derive(Clone, Copy)]
struct CacheEntry {
    ip: Option<IpAddr>,
    expires: Instant,
}

/// 解析器实例，跨 SOCKS5 连接 / UDP 会话共享（`Arc<Resolver>`）。
pub struct Resolver {
    mode: DnsMode,
    servers: Vec<SocketAddr>,
    timeout: Duration,
    cache_ttl: Duration,
    negative_ttl: Duration,
    tunnel: Option<Arc<Tunnel>>,
    /// 缓存按 (host, qtype) 分键。qtype=1 (A) / 28 (AAAA)
    cache: Mutex<HashMap<(String, u16), CacheEntry>>,
    /// Singleflight 去重：同一 (host, qtype) 的并发查询共用一次实际 DNS 请求。
    /// 后到的等待 `Notify`，醒来后从 cache 读结果。
    ///
    /// 持锁原则：**绝不**跨 await 持有此 Mutex（parking_lot 不可重入，跨 await
    /// 会死锁/阻塞 executor）。只在短临界区里 get/insert/remove，然后释放再 await。
    in_flight: Mutex<HashMap<(String, u16), Arc<Notify>>>,
    /// 测试 hook：若 Some，则 `query_record` 走 mock，不再调用真实 DNS。
    #[cfg(test)]
    mock: Option<Arc<tests::MockBackend>>,
}

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

impl Resolver {
    pub fn new(cfg: &DnsConfig, tunnel: Arc<Tunnel>) -> Self {
        Self {
            mode: cfg.mode,
            servers: cfg.servers.clone(),
            timeout: cfg.timeout,
            cache_ttl: cfg.cache_ttl,
            negative_ttl: cfg.negative_ttl,
            tunnel: Some(tunnel),
            cache: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            #[cfg(test)]
            mock: None,
        }
    }

    /// 仅 v4 解析；保留作为快速通道（DNS server 拨号等本身要 v4）。
    pub async fn resolve_v4(&self, host: &str, port: u16) -> Result<SocketAddrV4> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(SocketAddrV4::new(ip, port));
        }
        let key = host.to_ascii_lowercase();
        match self.lookup_cache(&key, QTYPE_A) {
            Some(Some(IpAddr::V4(v4))) => {
                counter!(M_DNS_CACHE_HIT).increment(1);
                return Ok(SocketAddrV4::new(v4, port));
            }
            Some(Some(IpAddr::V6(_))) => {
                // 不应该发生：A 槽里只会塞 v4
                counter!(M_DNS_CACHE_HIT).increment(1);
                return Err(Error::DnsNoIpv4(host.to_owned()));
            }
            Some(None) => {
                counter!(M_DNS_NEGATIVE_CACHE_HIT).increment(1);
                return Err(Error::DnsNoIpv4(host.to_owned()));
            }
            None => {}
        }
        counter!(M_DNS_QUERY).increment(1);
        // singleflight：并发同一 host 的 A 查询合并
        let ip = self.query_record_dedup(&key, QTYPE_A).await?;
        let v4 = match ip {
            IpAddr::V4(v) => v,
            IpAddr::V6(_) => return Err(Error::DnsNoIpv4(host.to_owned())),
        };
        Ok(SocketAddrV4::new(v4, port))
    }

    /// v0.2.1 双栈解析。返回候选 `SocketAddr` 列表，v6 排前面（happy eyeballs）。
    /// 列表非空保证至少一条；空 → Err。
    ///
    /// v0.3.x：加入 negative cache + singleflight。
    /// - 若 A、AAAA 两个槽都命中（含负缓存）→ 不再发起任何 DNS 查询。
    /// - 若只有一个槽命中 → 只查缺失那一边。
    /// - 同一 (host, qtype) 并发请求会被 singleflight 合并成一次。
    pub async fn resolve_dual(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        // 直接字面 IP：原样返回
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let key = host.to_ascii_lowercase();
        let cached_v4 = self.lookup_cache(&key, QTYPE_A);
        let cached_v6 = self.lookup_cache(&key, QTYPE_AAAA);

        // 两个槽都有缓存 entry（无论正负）→ 完全跳过查询
        if let (Some(v4), Some(v6)) = (cached_v4, cached_v6) {
            counter!(M_DNS_CACHE_HIT).increment(1);
            if v4.is_none() && v6.is_none() {
                counter!(M_DNS_NEGATIVE_CACHE_HIT).increment(1);
            }
            return merge_dual(v6, v4, port, host);
        }

        counter!(M_DNS_QUERY).increment(1);

        // 对每一侧：若已缓存（含负缓存）→ 用缓存；否则发起 singleflight 查询
        let v4_fut = async {
            match cached_v4 {
                Some(opt) => opt.ok_or_else(|| Error::DnsNoIpv4(host.to_owned())),
                None => self.query_record_dedup(&key, QTYPE_A).await,
            }
        };
        let v6_fut = async {
            match cached_v6 {
                Some(opt) => opt.ok_or_else(|| Error::other(format!("no AAAA record for {host}"))),
                None => self.query_record_dedup(&key, QTYPE_AAAA).await,
            }
        };
        let (a_res, aaaa_res) = tokio::join!(v4_fut, v6_fut);

        let v4 = a_res.ok().filter(|ip| matches!(ip, IpAddr::V4(_)));
        let v6 = aaaa_res.ok().filter(|ip| matches!(ip, IpAddr::V6(_)));
        merge_dual(v6, v4, port, host)
    }

    /// 返回：
    /// - `Some(Some(ip))`：正向缓存命中
    /// - `Some(None)`：负缓存命中（最近一次查询失败，未过期）
    /// - `None`：缓存中没有该 entry（或已过期被回收）
    fn lookup_cache(&self, host: &str, qtype: u16) -> Option<Option<IpAddr>> {
        let mut cache = self.cache.lock();
        let k = (host.to_owned(), qtype);
        if let Some(e) = cache.get(&k).copied() {
            if e.expires > Instant::now() {
                return Some(e.ip);
            }
            cache.remove(&k);
        }
        None
    }

    /// 写入缓存。`ip = None` 走 `negative_ttl`，`Some(_)` 走 `cache_ttl`。
    fn store_cache(&self, host: String, qtype: u16, ip: Option<IpAddr>) {
        let ttl = if ip.is_some() {
            self.cache_ttl
        } else {
            self.negative_ttl
        };
        let mut cache = self.cache.lock();
        if cache.len() > 1024 {
            cache.clear();
        }
        cache.insert(
            (host, qtype),
            CacheEntry {
                ip,
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Singleflight 包装：同一 (host, qtype) 并发请求合并成一次实际查询。
    ///
    /// 协议：
    /// 1. 进来先短锁查 `in_flight`：若已有 entry → 我们是 waiter，克隆 Notify，**释放锁**后 await。
    /// 2. 否则我们是 leader：插入新 Notify，**释放锁**，调用底层 query_record，
    ///    完成后把结果（含负缓存）写入 `cache`，**短锁**移除 in_flight，最后 notify_waiters。
    /// 3. waiter 醒来后从 cache 读结果；理论上 leader 一定已写入，但极端竞争（cache 立刻被
    ///    回收）下退化为直接调用 query_record，不会卡死。
    async fn query_record_dedup(&self, host: &str, qtype: u16) -> Result<IpAddr> {
        let k = (host.to_owned(), qtype);

        // 阶段 1：短锁，决定角色
        let role = {
            let mut g = self.in_flight.lock();
            if let Some(n) = g.get(&k) {
                Role::Waiter(n.clone())
            } else {
                let n = Arc::new(Notify::new());
                g.insert(k.clone(), n.clone());
                Role::Leader(n)
            }
        };

        match role {
            Role::Waiter(n) => {
                counter!(M_DNS_SINGLEFLIGHT_DEDUP).increment(1);
                // 必须先创建 notified() future 再 await，避免 leader 在我们 await
                // 之前 notify_waiters 导致丢醒。这是 Notify 的标准用法。
                let fut = n.notified();
                fut.await;
                // leader 已把结果写入 cache，从这里读出
                match self.lookup_cache(host, qtype) {
                    Some(Some(ip)) => Ok(ip),
                    Some(None) => Err(neg_err(host, qtype)),
                    None => {
                        // 极少见：cache 在 leader 写入到我们读取之间被清空（>1024 触发 clear）。
                        // 退化为直接查一次，不再 dedup，避免无限等待。
                        self.query_record(host, qtype).await
                    }
                }
            }
            Role::Leader(n) => {
                let result = self.query_record(host, qtype).await;
                // 写入缓存：成功 → 正向；任何失败 → 负缓存
                self.store_cache(host.to_owned(), qtype, result.as_ref().ok().copied());
                // 短锁移除自己，再 wake 所有 waiter
                {
                    let mut g = self.in_flight.lock();
                    g.remove(&k);
                }
                n.notify_waiters();
                result
            }
        }
    }

    /// 内部：查指定 qtype 的单条记录。
    async fn query_record(&self, host: &str, qtype: u16) -> Result<IpAddr> {
        #[cfg(test)]
        if let Some(m) = &self.mock {
            return m.query(host, qtype).await;
        }
        match self.mode {
            DnsMode::System => self.resolve_system(host, qtype).await,
            DnsMode::Tunnel => self.resolve_tunnel(host, qtype).await,
        }
    }

    async fn resolve_system(&self, host: &str, qtype: u16) -> Result<IpAddr> {
        // tokio::net::lookup_host 同时给 v4 + v6，按 qtype filter
        let host_port = format!("{host}:0");
        let fut = lookup_host(host_port);
        let iter = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| {
                counter!(M_DNS_QUERY_FAIL).increment(1);
                Error::other(format!("DNS 解析超时（system, qtype={qtype}）：{host}"))
            })?
            .map_err(|e| {
                counter!(M_DNS_QUERY_FAIL).increment(1);
                Error::Io(e)
            })?;
        for sa in iter {
            match (qtype, sa) {
                (QTYPE_A, SocketAddr::V4(v4)) => return Ok(IpAddr::V4(*v4.ip())),
                (QTYPE_AAAA, SocketAddr::V6(v6)) => return Ok(IpAddr::V6(*v6.ip())),
                _ => continue,
            }
        }
        counter!(M_DNS_QUERY_FAIL).increment(1);
        Err(if qtype == QTYPE_A {
            Error::DnsNoIpv4(host.to_owned())
        } else {
            Error::other(format!("no AAAA record for {host}"))
        })
    }

    async fn resolve_tunnel(&self, host: &str, qtype: u16) -> Result<IpAddr> {
        let query = build_dns_query(host, qtype);
        for server in &self.servers {
            let dest = match server {
                SocketAddr::V4(v4) => SocketAddr::V4(*v4),
                SocketAddr::V6(v6) => SocketAddr::V6(*v6),
            };
            match self.query_one(&query, dest, qtype).await {
                Ok(ip) => {
                    debug!(host, %ip, %dest, qtype, "tunnel DNS resolved");
                    return Ok(ip);
                }
                Err(e) => {
                    warn!(host, %dest, qtype, error = %e, "tunnel DNS failed, trying next");
                }
            }
        }
        counter!(M_DNS_QUERY_FAIL).increment(1);
        Err(if qtype == QTYPE_A {
            Error::DnsNoIpv4(host.to_owned())
        } else {
            Error::other(format!("no AAAA record for {host}"))
        })
    }

    async fn query_one(&self, query: &[u8], server: SocketAddr, qtype: u16) -> Result<IpAddr> {
        let tunnel = self.tunnel.as_ref().ok_or(Error::TunnelNotReady)?;
        let sock = tunnel.bind_udp()?;
        sock.send_to(query, server).await?;
        let mut buf = vec![0u8; 1500];
        let (n, _src) = sock.recv_from(&mut buf, self.timeout).await?;
        parse_dns_answer(&buf[..n], qtype)
    }
}

/// Singleflight 角色：要么是 leader（实际发起查询），要么是 waiter（等 leader）。
enum Role {
    Leader(Arc<Notify>),
    Waiter(Arc<Notify>),
}

/// 负缓存命中或错误路径的统一错误构造。
fn neg_err(host: &str, qtype: u16) -> Error {
    if qtype == QTYPE_A {
        Error::DnsNoIpv4(host.to_owned())
    } else {
        Error::other(format!("no AAAA record for {host}"))
    }
}

/// 把缓存/查询结果合并为 happy-eyeballs 顺序：v6 在前 → v4 在后。
fn merge_dual(
    v6: Option<IpAddr>,
    v4: Option<IpAddr>,
    port: u16,
    host: &str,
) -> Result<Vec<SocketAddr>> {
    let mut out = Vec::with_capacity(2);
    if let Some(IpAddr::V6(v6)) = v6 {
        out.push(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)));
    }
    if let Some(IpAddr::V4(v4)) = v4 {
        out.push(SocketAddr::V4(SocketAddrV4::new(v4, port)));
    }
    if out.is_empty() {
        return Err(Error::DnsNoIpv4(host.to_owned()));
    }
    trace!(host, candidates = ?out, "dual resolve result");
    Ok(out)
}

// ── DNS wire format ─────────────────────────────────────────────────────────

fn build_dns_query(host: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // 标准查询 + 递归
    buf.extend_from_slice(&1u16.to_be_bytes()); // qd
    buf.extend_from_slice(&0u16.to_be_bytes()); // an
    buf.extend_from_slice(&0u16.to_be_bytes()); // ns
    buf.extend_from_slice(&0u16.to_be_bytes()); // ar
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        let len = b.len().min(63) as u8;
        buf.push(len);
        buf.extend_from_slice(&b[..len as usize]);
    }
    buf.push(0);
    buf.extend_from_slice(&qtype.to_be_bytes()); // qtype = A or AAAA
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    buf
}

fn parse_dns_answer(reply: &[u8], qtype: u16) -> Result<IpAddr> {
    if reply.len() < 12 {
        return Err(Error::other("DNS reply too short"));
    }
    let qd = u16::from_be_bytes([reply[4], reply[5]]) as usize;
    let an = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    if an == 0 {
        return Err(Error::other("DNS reply has no answer (NXDOMAIN or empty)"));
    }
    let mut off = 12;
    for _ in 0..qd {
        off = skip_name(reply, off)?;
        off = off
            .checked_add(4)
            .ok_or_else(|| Error::other("DNS truncated"))?;
    }
    for _ in 0..an {
        off = skip_name(reply, off)?;
        if off + 10 > reply.len() {
            return Err(Error::other("DNS answer truncated"));
        }
        let rtype = u16::from_be_bytes([reply[off], reply[off + 1]]);
        let rdlen = u16::from_be_bytes([reply[off + 8], reply[off + 9]]) as usize;
        off += 10;
        if off + rdlen > reply.len() {
            return Err(Error::other("DNS rdata truncated"));
        }
        if rtype == qtype {
            match (qtype, rdlen) {
                (QTYPE_A, 4) => {
                    return Ok(IpAddr::V4(Ipv4Addr::new(
                        reply[off],
                        reply[off + 1],
                        reply[off + 2],
                        reply[off + 3],
                    )));
                }
                (QTYPE_AAAA, 16) => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&reply[off..off + 16]);
                    return Ok(IpAddr::V6(Ipv6Addr::from(o)));
                }
                _ => {}
            }
        }
        off += rdlen;
    }
    Err(Error::other(format!(
        "DNS reply has no qtype={qtype} record"
    )))
}

fn skip_name(buf: &[u8], mut off: usize) -> Result<usize> {
    loop {
        if off >= buf.len() {
            return Err(Error::other("DNS name out of bounds"));
        }
        let b = buf[off];
        if b == 0 {
            return Ok(off + 1);
        }
        if b & 0xc0 == 0xc0 {
            return Ok(off + 2);
        }
        off += 1 + b as usize;
    }
}

#[cfg(test)]
impl Resolver {
    /// 仅供测试：构造一个不依赖 Tunnel、走 mock backend 的 Resolver。
    pub(crate) fn new_for_test(
        cache_ttl: Duration,
        negative_ttl: Duration,
        mock: Arc<tests::MockBackend>,
    ) -> Self {
        Self {
            mode: DnsMode::System,
            servers: vec![],
            timeout: Duration::from_secs(1),
            cache_ttl,
            negative_ttl,
            tunnel: None,
            cache: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            mock: Some(mock),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 测试用 DNS backend：可记录调用次数、注入固定结果、延迟。
    pub(crate) struct MockBackend {
        pub call_count: AtomicUsize,
        pub delay: Duration,
        /// (host, qtype) → 结果。缺失则返回 NXDOMAIN 风格 Err。
        pub answers:
            parking_lot::Mutex<HashMap<(String, u16), std::result::Result<IpAddr, String>>>,
    }

    impl MockBackend {
        pub fn new(delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                call_count: AtomicUsize::new(0),
                delay,
                answers: parking_lot::Mutex::new(HashMap::new()),
            })
        }

        pub fn set(&self, host: &str, qtype: u16, ip: IpAddr) {
            self.answers.lock().insert((host.to_owned(), qtype), Ok(ip));
        }

        pub async fn query(&self, host: &str, qtype: u16) -> Result<IpAddr> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            let ans = self.answers.lock().get(&(host.to_owned(), qtype)).cloned();
            match ans {
                Some(Ok(ip)) => Ok(ip),
                Some(Err(msg)) => Err(Error::other(msg)),
                None => Err(neg_err(host, qtype)),
            }
        }
    }

    #[tokio::test]
    async fn resolve_dual_dedups_concurrent_queries() {
        // 100 个并发对同一 host 的 resolve_dual：底层 query_record 每个 qtype 只能被调一次。
        let mock = MockBackend::new(Duration::from_millis(50));
        mock.set(
            "example.com",
            QTYPE_A,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        );
        mock.set(
            "example.com",
            QTYPE_AAAA,
            IpAddr::V6(Ipv6Addr::from([
                0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
        );
        let resolver = Arc::new(Resolver::new_for_test(
            Duration::from_secs(60),
            Duration::from_secs(5),
            mock.clone(),
        ));

        let mut handles = Vec::new();
        for _ in 0..100 {
            let r = resolver.clone();
            handles.push(tokio::spawn(async move {
                r.resolve_dual("example.com", 443).await
            }));
        }
        for h in handles {
            let res = h.await.unwrap().expect("resolve should succeed");
            assert!(!res.is_empty());
        }
        // 100 个并发 × 2 个 qtype = 最多 200 次调用；singleflight 应该把它合并到 2 次。
        // 允许 race（第一个进入临界区前，可能少数同时插入）但绝不能 > 4。
        let calls = mock.call_count.load(Ordering::SeqCst);
        assert!(
            calls <= 4,
            "expected singleflight to merge to ~2 calls, got {calls}"
        );
        // 严格断言下界：至少有 1 次 A + 1 次 AAAA
        assert!(
            calls >= 2,
            "expected at least 2 calls (A + AAAA), got {calls}"
        );
    }

    #[tokio::test]
    async fn negative_cache_returns_err_quickly() {
        // 第一次：mock 中无该 host → query 返回 Err，存入负缓存
        // 第二次：lookup_cache 命中 Some(None) → 立刻 Err，绝不再调 query_record
        let mock = MockBackend::new(Duration::ZERO);
        // 不 set 任何 answer，query 会返回 neg_err
        let resolver = Resolver::new_for_test(
            Duration::from_secs(60),
            Duration::from_secs(5),
            mock.clone(),
        );

        // 第一次：失败
        let r1 = resolver.resolve_v4("nope.invalid", 80).await;
        assert!(r1.is_err());
        let calls_after_first = mock.call_count.load(Ordering::SeqCst);
        assert_eq!(
            calls_after_first, 1,
            "first call should hit backend exactly once"
        );

        // 第二次：负缓存命中，不应再调 backend
        let r2 = resolver.resolve_v4("nope.invalid", 80).await;
        assert!(r2.is_err());
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            calls_after_first,
            "second call must be served from negative cache, no new backend call"
        );

        // 第三次：另一个 host 走完整查询，证明负缓存只对原 host 生效
        let r3 = resolver.resolve_v4("other.invalid", 80).await;
        assert!(r3.is_err());
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            calls_after_first + 1,
            "different host must trigger a fresh backend call"
        );
    }

    #[tokio::test]
    async fn negative_cache_expires_after_ttl() {
        // 短 negative_ttl → 过期后再次查询应重新走 backend
        let mock = MockBackend::new(Duration::ZERO);
        let resolver = Resolver::new_for_test(
            Duration::from_secs(60),
            Duration::from_millis(50),
            mock.clone(),
        );

        let _ = resolver.resolve_v4("ghost.invalid", 80).await;
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(80)).await;

        let _ = resolver.resolve_v4("ghost.invalid", 80).await;
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            2,
            "expired negative cache should allow re-query"
        );
    }

    #[test]
    fn build_a_query() {
        let q = build_dns_query("example.com", QTYPE_A);
        assert_eq!(&q[0..2], &0x1234u16.to_be_bytes());
        // qtype = 0x0001 (A) 在末尾倒数 4 字节起
        let qtype_off = q.len() - 4;
        assert_eq!(&q[qtype_off..qtype_off + 2], &QTYPE_A.to_be_bytes());
    }

    #[test]
    fn build_aaaa_query() {
        let q = build_dns_query("example.com", QTYPE_AAAA);
        let qtype_off = q.len() - 4;
        assert_eq!(&q[qtype_off..qtype_off + 2], &QTYPE_AAAA.to_be_bytes());
    }

    #[test]
    fn parse_a_record() {
        let mut r = vec![];
        r.extend_from_slice(&0x1234u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // qd
        r.extend_from_slice(&1u16.to_be_bytes()); // an
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.push(7);
        r.extend_from_slice(b"example");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&QTYPE_A.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // answer: name ptr + type A + class IN + ttl + rdlen + rdata
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&QTYPE_A.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            parse_dns_answer(&r, QTYPE_A).unwrap(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn parse_aaaa_record() {
        let mut r = vec![];
        r.extend_from_slice(&0x1234u16.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.push(7);
        r.extend_from_slice(b"example");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&16u16.to_be_bytes());
        let v6_octets = [
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ];
        r.extend_from_slice(&v6_octets);
        assert_eq!(
            parse_dns_answer(&r, QTYPE_AAAA).unwrap(),
            IpAddr::V6(Ipv6Addr::from(v6_octets))
        );
    }
}
