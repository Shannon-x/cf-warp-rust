//! WireGuard configuration file parser.
//!
//! Parses standard WireGuard configuration files (.conf) using serde.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::dns::{DohResolver, DohServerConfig};
use crate::error::{Error, Result};
use crate::wireguard::WireGuardConfig;

/// Raw WireGuard configuration as parsed from the INI file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawWgConfig {
    interface: InterfaceSection,
    peer: PeerSection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InterfaceSection {
    private_key: String,
    address: String,
    #[serde(rename = "DNS")]
    dns: Option<String>,
    #[serde(rename = "MTU")]
    mtu: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PeerSection {
    public_key: String,
    endpoint: String,
    #[serde(default)]
    preshared_key: Option<String>,
    #[serde(default)]
    persistent_keepalive: Option<u16>,
    #[allow(dead_code)]
    allowed_ips: Option<String>,
}

/// Parsed WireGuard configuration file.
#[derive(Debug, Clone)]
pub struct WgConfigFile {
    /// Private key (base64 encoded in file).
    pub private_key: [u8; 32],
    /// Interface address (tunnel IP).
    pub address: Ipv4Addr,
    /// DNS server (optional).
    pub dns: Option<Ipv4Addr>,
    /// MTU for the tunnel interface (optional, defaults to 460).
    pub mtu: Option<u16>,
    /// Peer public key.
    pub peer_public_key: [u8; 32],
    /// Peer endpoint hostname or IP.
    pub endpoint_host: String,
    /// Peer endpoint port.
    pub endpoint_port: u16,
    /// Preshared key (optional).
    pub preshared_key: Option<[u8; 32]>,
    /// Persistent keepalive interval in seconds (optional).
    pub persistent_keepalive: Option<u16>,
}

impl WgConfigFile {
    /// Parse a WireGuard configuration file from the given path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            Error::ConfigParse(format!("Failed to read config file {:?}: {}", path.as_ref(), e))
        })?;
        Self::parse(&content)
    }

    /// Parse a WireGuard configuration from a string.
    pub fn parse(content: &str) -> Result<Self> {
        let raw: RawWgConfig =
            serde_ini::from_str(content).map_err(|e| Error::ConfigParse(e.to_string()))?;

        // Decode private key
        let private_key = decode_key(&raw.interface.private_key)?;

        // Parse address (strip CIDR notation if present)
        let ip_str = raw
            .interface
            .address
            .split('/')
            .next()
            .unwrap_or(&raw.interface.address);
        let address: Ipv4Addr = ip_str
            .parse()
            .map_err(|_| Error::InvalidAddress(raw.interface.address.clone()))?;

        // Parse DNS (take first if comma-separated)
        let dns = raw
            .interface
            .dns
            .as_ref()
            .and_then(|d| d.split(',').next())
            .map(|s| s.trim().parse())
            .transpose()
            .map_err(|_| Error::InvalidAddress("Invalid DNS address".into()))?;

        // Decode peer public key
        let peer_public_key = decode_key(&raw.peer.public_key)?;

        // Parse endpoint
        let (endpoint_host, endpoint_port) = parse_endpoint(&raw.peer.endpoint)?;

        // Decode preshared key if present
        let preshared_key = raw
            .peer
            .preshared_key
            .as_ref()
            .map(|k| decode_key(k))
            .transpose()?;

        Ok(Self {
            private_key,
            address,
            dns,
            mtu: raw.interface.mtu,
            peer_public_key,
            endpoint_host,
            endpoint_port,
            preshared_key,
            persistent_keepalive: raw.peer.persistent_keepalive,
        })
    }

    /// Convert to WireGuardConfig, resolving the endpoint hostname via DoH if needed.
    /// Uses the default Cloudflare DNS for resolution.
    pub async fn into_wireguard_config(self) -> Result<WireGuardConfig> {
        self.into_wireguard_config_with_dns(DohServerConfig::default()).await
    }

    /// Convert to WireGuardConfig, resolving the endpoint hostname via DoH with custom DNS.
    ///
    /// # Arguments
    ///
    /// * `dns_config` - The DNS server configuration to use for resolving the endpoint hostname.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wireguard_netstack::{WgConfigFile, DohServerConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = WgConfigFile::from_file("wg.conf")?
    ///     .into_wireguard_config_with_dns(DohServerConfig::google())
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn into_wireguard_config_with_dns(self, dns_config: DohServerConfig) -> Result<WireGuardConfig> {
        // First try to parse as IP:port, otherwise resolve via DoH
        let peer_endpoint =
            match format!("{}:{}", self.endpoint_host, self.endpoint_port).parse() {
                Ok(addr) => addr,
                Err(_) => {
                    // Resolve using DNS-over-HTTPS (direct mode, before tunnel is up)
                    log::info!(
                        "Resolving WireGuard endpoint '{}' via DoH ({})...",
                        self.endpoint_host,
                        dns_config.hostname
                    );
                    let doh_resolver = DohResolver::new_direct_with_config(dns_config);
                    doh_resolver
                        .resolve_addr(&self.endpoint_host, self.endpoint_port)
                        .await?
                }
            };

        log::info!("WireGuard endpoint resolved to: {}", peer_endpoint);

        Ok(WireGuardConfig {
            private_key: self.private_key,
            peer_public_key: self.peer_public_key,
            peer_endpoint,
            tunnel_ip: self.address,
            preshared_key: self.preshared_key,
            keepalive_seconds: self.persistent_keepalive.or(Some(25)), // Default to 25s if not specified
            mtu: self.mtu,
        })
    }
}

/// Decode a base64-encoded 32-byte key.
fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|_| Error::InvalidKey(b64.to_string()))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| Error::InvalidKey(format!("Key must be 32 bytes, got {} bytes", v.len())))
}

/// Parse an endpoint string (host:port).
fn parse_endpoint(endpoint: &str) -> Result<(String, u16)> {
    // Handle IPv6 addresses in brackets: [::1]:51820
    if endpoint.starts_with('[') {
        if let Some(bracket_end) = endpoint.find(']') {
            let host = endpoint[1..bracket_end].to_string();
            let port_str = endpoint[bracket_end + 1..].trim_start_matches(':');
            let port: u16 = port_str
                .parse()
                .map_err(|_| Error::InvalidEndpoint(endpoint.to_string()))?;
            return Ok((host, port));
        }
    }

    // Handle hostname:port or IPv4:port
    if let Some((host, port_str)) = endpoint.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|_| Error::InvalidEndpoint(endpoint.to_string()))?;
        Ok((host.to_string(), port))
    } else {
        Err(Error::InvalidEndpoint(format!(
            "Invalid endpoint format (expected host:port): {}",
            endpoint
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let config_str = r#"
[Interface]
PrivateKey = eC3sErLXd5A7z3FTJnrb55uuxlazlDM40HQmWZrb6Vc=
Address = 192.168.3.4/32
DNS = 192.168.3.1

[Peer]
PublicKey = EISEG38ycR6D7nK0m+mnacAM9HfXzdqcO1mO5LNs6jU=
AllowedIPs = 0.0.0.0/0
Endpoint = direct.casarizzotti.com:51820
"#;

        let config = WgConfigFile::parse(config_str).unwrap();
        assert_eq!(config.address, "192.168.3.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(config.dns, Some("192.168.3.1".parse().unwrap()));
        assert_eq!(config.endpoint_host, "direct.casarizzotti.com");
        assert_eq!(config.endpoint_port, 51820);
    }

    #[test]
    fn test_parse_endpoint() {
        // IPv4
        let (host, port) = parse_endpoint("1.2.3.4:51820").unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 51820);

        // Hostname
        let (host, port) = parse_endpoint("example.com:51820").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 51820);

        // IPv6
        let (host, port) = parse_endpoint("[::1]:51820").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 51820);
    }
}
