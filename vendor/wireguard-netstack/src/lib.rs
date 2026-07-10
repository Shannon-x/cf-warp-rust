//! Userspace WireGuard tunnel with TCP/IP network stack.
//!
//! This crate provides:
//! - WireGuard tunnel implementation using gotatun
//! - Userspace TCP/IP stack using smoltcp
//! - DNS-over-HTTPS resolver for privacy (with configurable DNS servers)
//! - High-level `ManagedTunnel` for easy integration
//!
//! # DNS Configuration
//!
//! You can configure different DNS servers for:
//! - **Pre-connection (direct mode)**: Used before the WireGuard tunnel is established
//! - **Post-connection (tunnel mode)**: Used after the tunnel is up, queries go through VPN
//!
//! ```no_run
//! use wireguard_netstack::{WgConfigFile, DohServerConfig, DnsConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Use Google DNS for resolving the WireGuard endpoint
//! let config = WgConfigFile::from_file("wg.conf")?
//!     .into_wireguard_config_with_dns(DohServerConfig::google())
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use wireguard_netstack::{ManagedTunnel, WgConfigFile, TcpConnection};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load WireGuard configuration
//!     let config = WgConfigFile::from_file("wg.conf")?
//!         .into_wireguard_config()
//!         .await?;
//!     
//!     // Connect (handles all background tasks automatically)
//!     let tunnel = ManagedTunnel::connect(config).await?;
//!     
//!     // Create a TCP connection through the tunnel
//!     let addr = "93.184.216.34:80".parse()?;
//!     let conn = TcpConnection::connect(tunnel.netstack(), addr).await?;
//!     
//!     // Use the connection...
//!     conn.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
//!     
//!     // Graceful shutdown
//!     tunnel.shutdown().await;
//!     Ok(())
//! }
//! ```

#[cfg(feature = "config-file")]
pub mod config;
#[cfg(feature = "doh")]
pub mod dns;
pub mod error;
pub mod netstack;
pub mod tunnel;
pub mod wireguard;

// Re-export main types
#[cfg(feature = "config-file")]
pub use config::WgConfigFile;
#[cfg(feature = "doh")]
pub use dns::{DnsConfig, DohResolver, DohServerConfig};
pub use error::{Error, Result};
pub use netstack::{NetStack, TcpConnection, UdpHandle, DEFAULT_MTU};
pub use tunnel::ManagedTunnel;
pub use wireguard::{WireGuardConfig, WireGuardTunnel};
