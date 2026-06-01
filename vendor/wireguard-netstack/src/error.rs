//! Error types for wireguard-netstack.

use std::net::SocketAddr;

/// Result type alias for wireguard-netstack operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in wireguard-netstack.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse WireGuard config: {0}")]
    ConfigParse(String),

    #[error("Invalid base64 key: {0}")]
    InvalidKey(String),

    #[error("Invalid endpoint format: {0}")]
    InvalidEndpoint(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("DNS resolution failed for '{hostname}': {message}")]
    DnsResolution { hostname: String, message: String },

    #[error("All DoH servers failed")]
    DnsAllServersFailed,

    #[error("No DNS records found for '{0}'")]
    DnsNoRecords(String),

    #[error("DNS error: RCODE={0}")]
    DnsError(u16),

    #[error("DNS response too short")]
    DnsResponseTooShort,

    #[error("DNS name extends beyond packet")]
    DnsNameTooLong,

    #[error("DNS label too long: {0}")]
    DnsLabelTooLong(String),

    #[error("Invalid HTTP response: {0}")]
    InvalidHttpResponse(String),

    #[error("DoH server returned error: {0}")]
    DohServerError(String),

    #[error("WireGuard handshake timeout after {0:?}")]
    HandshakeTimeout(std::time::Duration),

    #[error("Failed to create WireGuard tunnel: {0}")]
    TunnelCreation(String),

    #[error("TCP connection to {addr} failed: {message}")]
    TcpConnect { addr: SocketAddr, message: String },

    #[error("TCP connection failed: {0}")]
    TcpConnectGeneric(String),

    #[error("TCP connection timeout")]
    TcpTimeout,

    #[error("TCP send failed: {0}")]
    TcpSend(String),

    #[error("TCP receive failed: {0}")]
    TcpRecv(String),

    #[error("Read timeout")]
    ReadTimeout,

    #[error("Write timeout")]
    WriteTimeout,

    #[error("Short write: {written} of {expected} bytes")]
    ShortWrite { written: usize, expected: usize },

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("IPv6 not supported")]
    Ipv6NotSupported,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),
}
