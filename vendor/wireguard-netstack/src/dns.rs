//! DNS-over-HTTPS (DoH) resolver with configurable DNS servers.
//!
//! This module provides DNS resolution using DNS-over-HTTPS. It can work in two modes:
//!
//! 1. **Direct mode**: Uses regular TCP/TLS connections (for use before WireGuard is up)
//! 2. **Tunnel mode**: Uses the WireGuard tunnel for DNS queries
//!
//! Both modes ensure DNS privacy by using encrypted HTTPS connections.
//!
//! # Configurable DNS Servers
//!
//! You can configure different DNS servers for:
//! - **Pre-connection (direct mode)**: Used before the WireGuard tunnel is established
//! - **Post-connection (tunnel mode)**: Used after the tunnel is up, queries go through VPN
//!
//! By default, Cloudflare DNS (1.1.1.1, 1.0.0.1) is used.

use crate::error::{Error, Result};
use crate::netstack::{NetStack, TcpConnection};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Configuration for a DNS-over-HTTPS server.
#[derive(Debug, Clone)]
pub struct DohServerConfig {
    /// The hostname of the DoH server (used for TLS SNI and Host header).
    pub hostname: String,
    /// The IP addresses of the DoH server (we try these in order).
    /// These must be hardcoded since we can't resolve the DoH server using DoH itself.
    pub ips: Vec<Ipv4Addr>,
}

impl DohServerConfig {
    /// Create a new DoH server configuration.
    pub fn new(hostname: impl Into<String>, ips: Vec<Ipv4Addr>) -> Self {
        Self {
            hostname: hostname.into(),
            ips,
        }
    }

    /// Cloudflare DNS (1.1.1.1, 1.0.0.1) - the default.
    pub fn cloudflare() -> Self {
        Self {
            hostname: "1dot1dot1dot1.cloudflare-dns.com".into(),
            ips: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        }
    }

    /// Google DNS (8.8.8.8, 8.8.4.4).
    pub fn google() -> Self {
        Self {
            hostname: "dns.google".into(),
            ips: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        }
    }

    /// Quad9 DNS (9.9.9.9, 149.112.112.112).
    pub fn quad9() -> Self {
        Self {
            hostname: "dns.quad9.net".into(),
            ips: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        }
    }

    /// AdGuard DNS (94.140.14.14, 94.140.15.15).
    pub fn adguard() -> Self {
        Self {
            hostname: "dns.adguard-dns.com".into(),
            ips: vec![Ipv4Addr::new(94, 140, 14, 14), Ipv4Addr::new(94, 140, 15, 15)],
        }
    }

    /// NextDNS - requires your NextDNS configuration ID.
    /// The IPs are the anycast addresses for NextDNS.
    pub fn nextdns(config_id: &str) -> Self {
        Self {
            hostname: format!("{}.dns.nextdns.io", config_id),
            ips: vec![Ipv4Addr::new(45, 90, 28, 0), Ipv4Addr::new(45, 90, 30, 0)],
        }
    }
}

impl Default for DohServerConfig {
    fn default() -> Self {
        Self::cloudflare()
    }
}

/// DNS configuration for the library.
///
/// Allows configuring different DNS servers for pre-connection (direct mode)
/// and post-connection (tunnel mode) DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS server to use before the WireGuard tunnel is established.
    /// This is used to resolve the WireGuard endpoint hostname.
    pub pre_connection: DohServerConfig,
    /// DNS server to use after the WireGuard tunnel is established.
    /// All DNS queries will go through the VPN tunnel.
    pub post_connection: DohServerConfig,
}

impl DnsConfig {
    /// Create a new DNS configuration with the same server for both modes.
    pub fn new(server: DohServerConfig) -> Self {
        Self {
            pre_connection: server.clone(),
            post_connection: server,
        }
    }

    /// Create a DNS configuration with different servers for pre and post connection.
    pub fn with_different_servers(pre_connection: DohServerConfig, post_connection: DohServerConfig) -> Self {
        Self {
            pre_connection,
            post_connection,
        }
    }

    /// Use Cloudflare DNS for both modes (default).
    pub fn cloudflare() -> Self {
        Self::new(DohServerConfig::cloudflare())
    }

    /// Use Google DNS for both modes.
    pub fn google() -> Self {
        Self::new(DohServerConfig::google())
    }

    /// Use Quad9 DNS for both modes.
    pub fn quad9() -> Self {
        Self::new(DohServerConfig::quad9())
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self::cloudflare()
    }
}

/// DNS cache entry.
#[derive(Clone)]
struct CacheEntry {
    addresses: Vec<Ipv4Addr>,
    expires_at: Instant,
}

/// Transport mode for DoH queries.
#[derive(Clone)]
enum Transport {
    /// Use regular TCP connections (direct internet access).
    Direct,
    /// Use WireGuard tunnel for connections.
    Tunnel(Arc<NetStack>),
}

/// A DNS-over-HTTPS resolver with configurable DNS servers.
///
/// This resolver can work in two modes:
/// - Direct: Uses regular TCP/TLS for DNS queries (before WireGuard is up)
/// - Tunnel: Routes DNS queries through the WireGuard tunnel
///
/// # Example
///
/// ```no_run
/// use wireguard_netstack::{DohResolver, DohServerConfig};
///
/// // Use default Cloudflare DNS
/// let resolver = DohResolver::new_direct();
///
/// // Use custom DNS server
/// let resolver = DohResolver::new_direct_with_config(DohServerConfig::google());
/// ```
pub struct DohResolver {
    transport: Transport,
    tls_connector: TlsConnector,
    /// DNS cache.
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Cache TTL (default 5 minutes).
    cache_ttl: Duration,
    /// DoH server configuration.
    server_config: DohServerConfig,
}

impl DohResolver {
    /// Create a new DoH resolver that uses the WireGuard tunnel with default Cloudflare DNS.
    pub fn new_tunneled(netstack: Arc<NetStack>) -> Self {
        Self::new_tunneled_with_config(netstack, DohServerConfig::default())
    }

    /// Create a new DoH resolver that uses the WireGuard tunnel with custom DNS config.
    pub fn new_tunneled_with_config(netstack: Arc<NetStack>, config: DohServerConfig) -> Self {
        Self::new_with_transport(Transport::Tunnel(netstack), config)
    }

    /// Create a new DoH resolver that uses direct TCP connections with default Cloudflare DNS.
    /// Use this before the WireGuard tunnel is established.
    pub fn new_direct() -> Self {
        Self::new_direct_with_config(DohServerConfig::default())
    }

    /// Create a new DoH resolver that uses direct TCP connections with custom DNS config.
    /// Use this before the WireGuard tunnel is established.
    pub fn new_direct_with_config(config: DohServerConfig) -> Self {
        Self::new_with_transport(Transport::Direct, config)
    }

    /// Create a resolver with the specified transport and server configuration.
    fn new_with_transport(transport: Transport, server_config: DohServerConfig) -> Self {
        // Install ring as the crypto provider (may already be installed)
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Set up rustls with webpki roots
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        Self {
            transport,
            tls_connector,
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300), // 5 minutes
            server_config,
        }
    }

    /// Get the current server configuration.
    pub fn server_config(&self) -> &DohServerConfig {
        &self.server_config
    }

    /// Resolve a hostname to IPv4 addresses using DNS-over-HTTPS.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<Ipv4Addr>> {
        // Check if it's already an IP address
        if let Ok(ip) = hostname.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }

        // Check cache
        {
            let cache = self.cache.lock();
            if let Some(entry) = cache.get(hostname) {
                if entry.expires_at > Instant::now() {
                    log::debug!("DNS cache hit for {}", hostname);
                    return Ok(entry.addresses.clone());
                }
            }
        }

        let mode = match &self.transport {
            Transport::Direct => "direct",
            Transport::Tunnel(_) => "tunneled",
        };
        log::info!("Resolving {} via DoH ({})", hostname, mode);

        // Try each DoH server IP
        let mut last_error = None;
        for doh_ip in &self.server_config.ips {
            match self.query_doh(*doh_ip, hostname).await {
                Ok(addrs) => {
                    // Cache the result
                    {
                        let mut cache = self.cache.lock();
                        cache.insert(
                            hostname.to_string(),
                            CacheEntry {
                                addresses: addrs.clone(),
                                expires_at: Instant::now() + self.cache_ttl,
                            },
                        );
                    }
                    return Ok(addrs);
                }
                Err(e) => {
                    log::warn!("DoH query to {} failed: {}", doh_ip, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(Error::DnsAllServersFailed))
    }

    /// Resolve a hostname to a single socket address.
    pub async fn resolve_addr(&self, hostname: &str, port: u16) -> Result<SocketAddr> {
        let addrs = self.resolve(hostname).await?;
        let ip = addrs
            .into_iter()
            .next()
            .ok_or_else(|| Error::DnsNoRecords(hostname.to_string()))?;
        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }

    /// Query a DoH server for DNS records.
    async fn query_doh(&self, doh_ip: Ipv4Addr, hostname: &str) -> Result<Vec<Ipv4Addr>> {
        let addr = SocketAddr::V4(SocketAddrV4::new(doh_ip, 443));

        // Build the DNS wire format query
        let dns_query = build_dns_query(hostname)?;

        // Build HTTP/1.1 request for DNS-over-HTTPS (using POST with application/dns-message)
        let http_request = format!(
            "POST /dns-query HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            self.server_config.hostname,
            dns_query.len()
        );

        // Connect and perform TLS handshake based on transport mode
        let response = match &self.transport {
            Transport::Direct => {
                self.query_direct(addr, &http_request, &dns_query).await?
            }
            Transport::Tunnel(netstack) => {
                self.query_tunneled(netstack.clone(), addr, &http_request, &dns_query)
                    .await?
            }
        };

        log::debug!("Received {} bytes from DoH server", response.len());

        // Parse HTTP response
        parse_doh_response(&response, hostname)
    }

    /// Query DoH server using direct TCP connection.
    async fn query_direct(
        &self,
        addr: SocketAddr,
        http_request: &str,
        dns_query: &[u8],
    ) -> Result<Vec<u8>> {
        // Connect via regular TCP
        let tcp_stream = TcpStream::connect(addr).await?;

        // TLS handshake
        let server_name = rustls::pki_types::ServerName::try_from(self.server_config.hostname.clone())
            .map_err(|e| Error::TlsHandshake(format!("Invalid server name: {}", e)))?;

        log::debug!("Starting TLS handshake with DoH server {} (direct)", addr);
        let mut tls_stream = self
            .tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| Error::TlsHandshake(e.to_string()))?;

        log::debug!("TLS handshake completed, sending DNS query");

        // Send HTTP request
        tls_stream.write_all(http_request.as_bytes()).await?;
        tls_stream.write_all(dns_query).await?;
        tls_stream.flush().await?;

        log::debug!("DNS query sent, waiting for response");

        // Read response
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tls_stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 4 && response_complete(&response) {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(response)
    }

    /// Query DoH server using WireGuard tunnel.
    async fn query_tunneled(
        &self,
        netstack: Arc<NetStack>,
        addr: SocketAddr,
        http_request: &str,
        dns_query: &[u8],
    ) -> Result<Vec<u8>> {
        // Connect via WireGuard tunnel
        let tcp_conn = TcpConnection::connect(netstack, addr).await?;

        let tcp_stream = TunnelTcpStream {
            conn: Arc::new(tcp_conn),
        };

        // TLS handshake
        let server_name = rustls::pki_types::ServerName::try_from(self.server_config.hostname.clone())
            .map_err(|e| Error::TlsHandshake(format!("Invalid server name: {}", e)))?;

        log::debug!(
            "Starting TLS handshake with DoH server {} (tunneled)",
            addr
        );
        let mut tls_stream = self
            .tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| Error::TlsHandshake(e.to_string()))?;

        log::debug!("TLS handshake completed, sending DNS query");

        // Send HTTP request
        tls_stream.write_all(http_request.as_bytes()).await?;
        tls_stream.write_all(dns_query).await?;
        tls_stream.flush().await?;

        log::debug!("DNS query sent, waiting for response");

        // Read response
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tls_stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 4 && response_complete(&response) {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(response)
    }
}

/// Check if we've received a complete HTTP response.
fn response_complete(data: &[u8]) -> bool {
    // Look for end of headers
    if let Some(header_end) = find_header_end(data) {
        // Parse Content-Length if present
        let headers = &data[..header_end];
        if let Some(content_length) = parse_content_length(headers) {
            let body_start = header_end + 4; // Skip \r\n\r\n
            let body_len = data.len().saturating_sub(body_start);
            return body_len >= content_length;
        }
        // For chunked encoding or connection close, assume complete if we see 0-length read
        return true;
    }
    false
}

/// Find the position of the header/body separator.
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Parse Content-Length header.
fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let headers_str = std::str::from_utf8(headers).ok()?;
    for line in headers_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let value = line.split(':').nth(1)?.trim();
            return value.parse().ok();
        }
    }
    None
}

/// Build a DNS query in wire format.
fn build_dns_query(hostname: &str) -> Result<Vec<u8>> {
    let mut query = Vec::new();

    // Transaction ID (random)
    let id: u16 = rand::random();
    query.extend_from_slice(&id.to_be_bytes());

    // Flags: standard query, recursion desired
    query.extend_from_slice(&[0x01, 0x00]); // QR=0, OPCODE=0, RD=1

    // QDCOUNT = 1
    query.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]);
    // NSCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]);
    // ARCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]);

    // Question section
    // Encode hostname as DNS name
    for label in hostname.split('.') {
        if label.len() > 63 {
            return Err(Error::DnsLabelTooLong(label.to_string()));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // Root label

    // QTYPE = A (1)
    query.extend_from_slice(&[0x00, 0x01]);
    // QCLASS = IN (1)
    query.extend_from_slice(&[0x00, 0x01]);

    Ok(query)
}

/// Parse DNS-over-HTTPS response.
fn parse_doh_response(response: &[u8], hostname: &str) -> Result<Vec<Ipv4Addr>> {
    // Find header/body separator
    let header_end = find_header_end(response)
        .ok_or_else(|| Error::InvalidHttpResponse("no header end found".into()))?;

    let body_start = header_end + 4;
    if body_start >= response.len() {
        return Err(Error::InvalidHttpResponse("empty body".into()));
    }

    // Check HTTP status
    let headers =
        std::str::from_utf8(&response[..header_end]).map_err(|_| Error::InvalidHttpResponse("invalid headers".into()))?;

    let status_line = headers.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        return Err(Error::DohServerError(status_line.to_string()));
    }

    let dns_response = &response[body_start..];
    parse_dns_response(dns_response, hostname)
}

/// Parse DNS response wire format.
fn parse_dns_response(data: &[u8], hostname: &str) -> Result<Vec<Ipv4Addr>> {
    if data.len() < 12 {
        return Err(Error::DnsResponseTooShort);
    }

    // Parse header
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;

    if rcode != 0 {
        return Err(Error::DnsError(rcode));
    }

    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return Err(Error::DnsNoRecords(hostname.to_string()));
    }

    log::debug!("DNS response has {} answers", ancount);

    // Skip header and question section
    let mut pos = 12;

    // Skip question section (QDCOUNT questions)
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer section
    let mut addresses = Vec::new();
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        // Skip name
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let _ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;

        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        // Type A = 1
        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            log::debug!("Resolved {} -> {}", hostname, ip);
            addresses.push(ip);
        }

        pos += rdlength;
    }

    if addresses.is_empty() {
        return Err(Error::DnsNoRecords(hostname.to_string()));
    }

    Ok(addresses)
}

/// Skip a DNS name (handles compression).
fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= data.len() {
            return Err(Error::DnsNameTooLong);
        }

        let len = data[pos] as usize;

        // Check for compression pointer
        if len & 0xC0 == 0xC0 {
            // Compression pointer is 2 bytes
            return Ok(pos + 2);
        }

        // Check for end of name
        if len == 0 {
            return Ok(pos + 1);
        }

        // Skip label
        pos += 1 + len;
    }
}

/// A TCP stream wrapper for tunneled DoH connections.
pub(crate) struct TunnelTcpStream {
    conn: Arc<TcpConnection>,
}

impl tokio::io::AsyncRead for TunnelTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let conn = self.conn.clone();
        let unfilled = buf.initialize_unfilled();

        conn.netstack.poll();

        if conn.netstack.can_recv(conn.handle) {
            match conn.netstack.recv(conn.handle, unfilled) {
                Ok(n) if n > 0 => {
                    buf.advance(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                Ok(_) => {}
                Err(e) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )));
                }
            }
        }

        if !conn.netstack.may_recv(conn.handle) {
            return std::task::Poll::Ready(Ok(()));
        }

        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            waker.wake();
        });

        std::task::Poll::Pending
    }
}

impl tokio::io::AsyncWrite for TunnelTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let conn = self.conn.clone();

        conn.netstack.poll();

        if conn.netstack.can_send(conn.handle) {
            match conn.netstack.send(conn.handle, buf) {
                Ok(n) => {
                    conn.netstack.poll();
                    return std::task::Poll::Ready(Ok(n));
                }
                Err(e) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )));
                }
            }
        }

        if !conn.netstack.may_send(conn.handle) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Connection closed",
            )));
        }

        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            waker.wake();
        });

        std::task::Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.conn.netstack.poll();
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.conn.shutdown();
        self.conn.netstack.poll();
        std::task::Poll::Ready(Ok(()))
    }
}
