//! 跨模块统一错误类型。各子模块的具体错误通过 `From` 向上汇聚到这里。

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("warp registration: {0}")]
    WarpApi(#[from] warp_wireguard_gen::Error),

    #[error("wireguard netstack: {0}")]
    Netstack(#[from] wireguard_netstack::Error),

    #[error("tunnel not ready")]
    TunnelNotReady,

    #[error("DNS lookup returned no IPv4 result for {0}")]
    DnsNoIpv4(String),

    #[error("SOCKS5: {0}")]
    Socks(#[from] fast_socks5::SocksError),

    #[error("SOCKS5 server: {0}")]
    SocksServer(#[from] fast_socks5::server::SocksServerError),

    #[error("upstream dial failed for {addr}: {source}")]
    Dial {
        addr: SocketAddr,
        #[source]
        source: Box<wireguard_netstack::Error>,
    },

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("figment: {0}")]
    Figment(#[from] figment::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
