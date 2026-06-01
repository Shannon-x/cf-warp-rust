//! DNS 解析层，统一服务 SOCKS5 CONNECT（Domain ATYP）与 UDP ASSOCIATE。
//!
//! 两种模式：
//! - `System`：调宿主 `tokio::net::lookup_host`（默认；最快、最兼容；但 DNS 报文不走隧道，泄漏域名）
//! - `Tunnel`：在 WARP 隧道内开 UDP socket 拨 `[1.1.1.1:53, 1.0.0.1:53]`，手写 DNS wire format
//!   解析 A 记录；走 LRU 缓存（默认 60s TTL）后几乎无 RTT 损耗
//!
//! Cache key 是 `host`（小写化），不带端口；命中后端口由调用方拼回去。

use crate::config::{DnsConfig, DnsMode};
use crate::error::{Error, Result};
use crate::metrics::{M_DNS_CACHE_HIT, M_DNS_QUERY, M_DNS_QUERY_FAIL};
use crate::tunnel::Tunnel;
use metrics::counter;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tracing::{debug, trace, warn};

/// 解析器实例，跨 SOCKS5 连接 / UDP 会话共享（`Arc<Resolver>`）。
pub struct Resolver {
    mode: DnsMode,
    servers: Vec<SocketAddr>,
    timeout: Duration,
    cache_ttl: Duration,
    tunnel: Arc<Tunnel>,
    cache: Mutex<HashMap<String, (Ipv4Addr, Instant)>>,
}

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

    /// 解析 host → IPv4，拼上 port 返回。
    /// host 可能是 "example.com"（域名）或 "1.2.3.4"（直接是 IP 文本）。
    pub async fn resolve_v4(&self, host: &str, port: u16) -> Result<SocketAddrV4> {
        // 先看是不是直接的 IPv4 文本，省一次 DNS
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(SocketAddrV4::new(ip, port));
        }

        let key = host.to_ascii_lowercase();
        // 缓存命中
        if let Some(ip) = self.lookup_cache(&key) {
            counter!(M_DNS_CACHE_HIT).increment(1);
            trace!(host = %key, %ip, "dns cache hit");
            return Ok(SocketAddrV4::new(ip, port));
        }

        counter!(M_DNS_QUERY).increment(1);
        let ip = match self.mode {
            DnsMode::System => self.resolve_system(&key).await?,
            DnsMode::Tunnel => self.resolve_tunnel(&key).await?,
        };
        self.store_cache(key, ip);
        Ok(SocketAddrV4::new(ip, port))
    }

    fn lookup_cache(&self, host: &str) -> Option<Ipv4Addr> {
        let mut cache = self.cache.lock();
        if let Some((ip, at)) = cache.get(host).copied() {
            if at.elapsed() < self.cache_ttl {
                return Some(ip);
            }
            cache.remove(host);
        }
        None
    }

    fn store_cache(&self, host: String, ip: Ipv4Addr) {
        let mut cache = self.cache.lock();
        // 简易上限：超过 1024 条清空（不维护 LRU 顺序——简化实现，TTL 自然回收）
        if cache.len() > 1024 {
            cache.clear();
        }
        cache.insert(host, (ip, Instant::now()));
    }

    async fn resolve_system(&self, host: &str) -> Result<Ipv4Addr> {
        // 用 host:0 让 tokio 走系统 resolver，端口可任意
        let host_port = format!("{host}:0");
        let fut = lookup_host(host_port);
        let iter = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| {
                counter!(M_DNS_QUERY_FAIL).increment(1);
                Error::other(format!("DNS 解析超时（system）：{host}"))
            })?
            .map_err(|e| {
                counter!(M_DNS_QUERY_FAIL).increment(1);
                Error::Io(e)
            })?;
        for sa in iter {
            if let SocketAddr::V4(v4) = sa {
                return Ok(*v4.ip());
            }
        }
        counter!(M_DNS_QUERY_FAIL).increment(1);
        Err(Error::DnsNoIpv4(host.to_owned()))
    }

    /// 通过隧道内 UDP socket 拨 DNS server 查询 A 记录。
    /// 多个 server 串行尝试，首个成功的 IP 返回；全部失败才报错。
    async fn resolve_tunnel(&self, host: &str) -> Result<Ipv4Addr> {
        let query = build_dns_query(host);
        for server in &self.servers {
            let dest = match server {
                SocketAddr::V4(v4) => *v4,
                SocketAddr::V6(_) => continue, // netstack v4-only
            };
            match self.query_one(&query, dest).await {
                Ok(ip) => {
                    debug!(host, %ip, %dest, "tunnel DNS resolved");
                    return Ok(ip);
                }
                Err(e) => {
                    warn!(host, %dest, error = %e, "tunnel DNS query failed, trying next");
                }
            }
        }
        counter!(M_DNS_QUERY_FAIL).increment(1);
        Err(Error::DnsNoIpv4(host.to_owned()))
    }

    async fn query_one(&self, query: &[u8], server: SocketAddrV4) -> Result<Ipv4Addr> {
        let sock = self.tunnel.bind_udp()?;
        sock.send_to(query, server).await?;
        let mut buf = vec![0u8; 1500];
        let (n, _src) = sock.recv_from(&mut buf, self.timeout).await?;
        parse_dns_answer_a(&buf[..n])
    }
}

// ── DNS wire format ─────────────────────────────────────────────────────────
// 极简实现：只构造/解析 A 记录查询，够 SOCKS5 用。
// 报文结构 RFC 1035。

fn build_dns_query(host: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    // header: id, flags, qd, an, ns, ar
    buf.extend_from_slice(&0x1234u16.to_be_bytes()); // 固定 ID（我们一次一个 socket，无冲突）
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // 标准查询 + 递归
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
                                                // qname: 每 label 前 1 字节长度
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        // RFC 1035 单 label 最多 63 字节
        let len = b.len().min(63) as u8;
        buf.push(len);
        buf.extend_from_slice(&b[..len as usize]);
    }
    buf.push(0); // root
                 // qtype = A (1), qclass = IN (1)
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf
}

fn parse_dns_answer_a(reply: &[u8]) -> Result<Ipv4Addr> {
    if reply.len() < 12 {
        return Err(Error::other("DNS reply too short"));
    }
    let qd = u16::from_be_bytes([reply[4], reply[5]]) as usize;
    let an = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    if an == 0 {
        return Err(Error::other("DNS reply has no answer (NXDOMAIN or empty)"));
    }
    let mut off = 12;
    // 跳过 qd 个问题
    for _ in 0..qd {
        off = skip_name(reply, off)?;
        off = off
            .checked_add(4)
            .ok_or_else(|| Error::other("DNS truncated"))?; // qtype+qclass
    }
    // 遍历 answer
    for _ in 0..an {
        off = skip_name(reply, off)?;
        if off + 10 > reply.len() {
            return Err(Error::other("DNS answer truncated"));
        }
        let rtype = u16::from_be_bytes([reply[off], reply[off + 1]]);
        // class @ [+2..+4], ttl @ [+4..+8]
        let rdlen = u16::from_be_bytes([reply[off + 8], reply[off + 9]]) as usize;
        off += 10;
        if off + rdlen > reply.len() {
            return Err(Error::other("DNS rdata truncated"));
        }
        if rtype == 1 && rdlen == 4 {
            return Ok(Ipv4Addr::new(
                reply[off],
                reply[off + 1],
                reply[off + 2],
                reply[off + 3],
            ));
        }
        off += rdlen;
    }
    Err(Error::other("DNS reply has no A record"))
}

/// 跳过一个 DNS name（含压缩指针），返回 name 之后的偏移。
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
            // 压缩指针，长度 2 字节
            return Ok(off + 2);
        }
        off += 1 + b as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let q = build_dns_query("example.com");
        // 头 12 + qname (7 example) + 0 + 4 (type+class) = 12+8+1+4 = wait
        // "example" = 7 chars; "com" = 3 chars; len bytes each
        assert!(q.len() >= 12 + 1 + 7 + 1 + 3 + 1 + 4);
        // ID
        assert_eq!(&q[0..2], &0x1234u16.to_be_bytes());
        // qdcount = 1
        assert_eq!(&q[4..6], &1u16.to_be_bytes());
    }

    #[test]
    fn parse_real_a_record_reply() {
        // 构造一个模拟回包：id=0x1234，flags=0x8180，qd=1 an=1 ns=0 ar=0
        // question: example.com A IN
        // answer: pointer to qname (0xc00c) + type A(1) + class IN(1) + ttl 60 + rdlen 4 + 1.2.3.4
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
        r.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        r.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        r.extend_from_slice(&[0xc0, 0x0c]); // name pointer to offset 12
        r.extend_from_slice(&1u16.to_be_bytes()); // type A
        r.extend_from_slice(&1u16.to_be_bytes()); // class IN
        r.extend_from_slice(&60u32.to_be_bytes()); // ttl
        r.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        r.extend_from_slice(&[1, 2, 3, 4]);

        let ip = parse_dns_answer_a(&r).unwrap();
        assert_eq!(ip, Ipv4Addr::new(1, 2, 3, 4));
    }
}
