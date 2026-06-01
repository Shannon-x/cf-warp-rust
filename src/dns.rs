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
use crate::metrics::{M_DNS_CACHE_HIT, M_DNS_QUERY, M_DNS_QUERY_FAIL};
use crate::tunnel::Tunnel;
use metrics::counter;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tracing::{debug, trace, warn};

/// 缓存项：单条记录类型的解析结果
#[derive(Clone, Copy)]
struct CacheEntry {
    ip: IpAddr,
    expires: Instant,
}

/// 解析器实例，跨 SOCKS5 连接 / UDP 会话共享（`Arc<Resolver>`）。
pub struct Resolver {
    mode: DnsMode,
    servers: Vec<SocketAddr>,
    timeout: Duration,
    cache_ttl: Duration,
    tunnel: Arc<Tunnel>,
    /// 缓存按 (host, qtype) 分键。qtype=1 (A) / 28 (AAAA)
    cache: Mutex<HashMap<(String, u16), CacheEntry>>,
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
            tunnel,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// 仅 v4 解析；保留作为快速通道（DNS server 拨号等本身要 v4）。
    pub async fn resolve_v4(&self, host: &str, port: u16) -> Result<SocketAddrV4> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(SocketAddrV4::new(ip, port));
        }
        let key = host.to_ascii_lowercase();
        if let Some(IpAddr::V4(v4)) = self.lookup_cache(&key, QTYPE_A) {
            counter!(M_DNS_CACHE_HIT).increment(1);
            return Ok(SocketAddrV4::new(v4, port));
        }
        counter!(M_DNS_QUERY).increment(1);
        let ip = self.query_record(&key, QTYPE_A).await?;
        let v4 = match ip {
            IpAddr::V4(v) => v,
            IpAddr::V6(_) => return Err(Error::DnsNoIpv4(host.to_owned())),
        };
        self.store_cache(key, QTYPE_A, IpAddr::V4(v4));
        Ok(SocketAddrV4::new(v4, port))
    }

    /// v0.2.1 双栈解析。返回候选 `SocketAddr` 列表，v6 排前面（happy eyeballs）。
    /// 列表非空保证至少一条；空 → Err。
    pub async fn resolve_dual(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        // 直接字面 IP：原样返回
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let key = host.to_ascii_lowercase();
        let cached_v4 = self.lookup_cache(&key, QTYPE_A);
        let cached_v6 = self.lookup_cache(&key, QTYPE_AAAA);

        // 全缓存命中
        if cached_v4.is_some() || cached_v6.is_some() {
            counter!(M_DNS_CACHE_HIT).increment(1);
            return merge_dual(cached_v6, cached_v4, port, host);
        }

        counter!(M_DNS_QUERY).increment(1);
        // 并发查 A + AAAA，任一成功即用；二者都失败才 Err
        let (a_res, aaaa_res) = tokio::join!(
            self.query_record(&key, QTYPE_A),
            self.query_record(&key, QTYPE_AAAA),
        );

        if let Ok(IpAddr::V4(v4)) = a_res {
            self.store_cache(key.clone(), QTYPE_A, IpAddr::V4(v4));
        }
        if let Ok(IpAddr::V6(v6)) = aaaa_res {
            self.store_cache(key.clone(), QTYPE_AAAA, IpAddr::V6(v6));
        }

        let v4 = a_res.ok();
        let v6 = aaaa_res.ok();
        merge_dual(v6, v4, port, host)
    }

    fn lookup_cache(&self, host: &str, qtype: u16) -> Option<IpAddr> {
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

    fn store_cache(&self, host: String, qtype: u16, ip: IpAddr) {
        let mut cache = self.cache.lock();
        if cache.len() > 1024 {
            cache.clear();
        }
        cache.insert(
            (host, qtype),
            CacheEntry {
                ip,
                expires: Instant::now() + self.cache_ttl,
            },
        );
    }

    /// 内部：查指定 qtype 的单条记录。
    async fn query_record(&self, host: &str, qtype: u16) -> Result<IpAddr> {
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
        let sock = self.tunnel.bind_udp()?;
        sock.send_to(query, server).await?;
        let mut buf = vec![0u8; 1500];
        let (n, _src) = sock.recv_from(&mut buf, self.timeout).await?;
        parse_dns_answer(&buf[..n], qtype)
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
mod tests {
    use super::*;

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
