//! Cloudflare WARP API client implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use reqwest::Client;

use crate::error::{Error, Result};
use crate::keys::generate_keypair;
use crate::types::*;
use crate::{RegistrationOptions, WarpCredentials};
use wireguard_netstack::WireGuardConfig;

/// Cloudflare WARP API base URL.
const API_URL: &str = "https://api.cloudflareclient.com";

/// API version string (must match the official client).
const API_VERSION: &str = "v0a2483";

/// CF-Client-Version header value.
const CF_CLIENT_VERSION: &str = "a-6.81-2410012252.0";

/// Create an HTTP client with required headers and TLS 1.2 configuration.
///
/// Cloudflare's WARP API requires TLS 1.2 specifically and rejects TLS 1.3.
fn create_client(auth_token: Option<&str>, teams_jwt: Option<&str>) -> Result<Client> {
    // Configure rustls to use TLS 1.2 only (Cloudflare API requirement)
    // Use ring crypto provider explicitly
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .map_err(|e| Error::Tls(e.to_string()))?
    .with_root_certificates(Arc::new(rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }))
    .with_no_client_auth();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("cf-client-version"),
        reqwest::header::HeaderValue::from_static(CF_CLIENT_VERSION),
    );
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/json; charset=UTF-8"),
    );

    if let Some(token) = auth_token {
        let value = format!("Bearer {}", token)
            .parse()
            .map_err(|_| Error::InvalidResponse("Invalid access token header".to_string()))?;
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }

    // Add Teams JWT assertion header for Zero Trust enrollment
    if let Some(jwt) = teams_jwt {
        headers.insert(
            "CF-Access-Jwt-Assertion",
            jwt.parse()
                .map_err(|_| Error::InvalidResponse("Invalid JWT token format".to_string()))?,
        );
    }

    let builder = Client::builder()
        .use_preconfigured_tls(tls_config)
        .user_agent("1.1.1.1/6.81")
        .default_headers(headers)
        .http1_only()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .pool_idle_timeout(Duration::from_secs(30)); // No HTTP/2 to match official client behavior

    builder.build().map_err(Error::from)
}

/// Register a new device with Cloudflare WARP.
///
/// Supports both consumer WARP and Cloudflare for Teams (Zero Trust) enrollment.
pub async fn register(options: RegistrationOptions) -> Result<(WireGuardConfig, WarpCredentials)> {
    let (private_key, public_key) = generate_keypair();
    let public_key_b64 = STANDARD.encode(public_key);

    let is_teams = options.teams.is_some();

    // Create client with Teams JWT if provided
    let teams_jwt = options.teams.as_ref().map(|t| t.jwt_token.as_str());
    let client = create_client(None, teams_jwt)?;

    // Build registration request
    // For Teams enrollment: no tos, no device_type, include name and serial_number
    // For consumer WARP: include tos and device_type, no name/serial_number
    let register_req = if let Some(ref teams) = options.teams {
        log::info!("Registering device with Cloudflare for Teams (Zero Trust)...");
        RegisterRequest {
            fcm_token: String::new(),
            install_id: String::new(),
            key: public_key_b64,
            locale: "en_US".to_string(),
            model: options.device_model,
            tos: None,
            device_type: None,
            // For Teams enrollment, always send name and serial_number (even if empty)
            name: Some(teams.device_name.clone().unwrap_or_default()),
            serial_number: Some(teams.serial_number.clone().unwrap_or_default()),
        }
    } else {
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        log::info!("Registering new device with Cloudflare WARP...");
        RegisterRequest {
            fcm_token: String::new(),
            install_id: String::new(),
            key: public_key_b64,
            locale: "en_US".to_string(),
            model: options.device_model,
            tos: Some(timestamp),
            device_type: Some("Android".to_string()),
            name: None,
            serial_number: None,
        }
    };

    let resp: RegisterResponse = client
        .post(format!("{}/{}/reg", API_URL, API_VERSION))
        .json(&register_req)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    log::info!("Device registered successfully with ID: {}", resp.id);

    // Parse client_id from response config if present
    let client_id = parse_client_id(resp.config.client_id.as_deref())?;

    let mut credentials = WarpCredentials {
        device_id: resp.id,
        access_token: resp.token,
        private_key,
        license_key: resp.account.license,
        client_id,
        is_teams,
    };

    // Apply license key if provided (only for consumer WARP, not Teams)
    if !is_teams {
        if let Some(ref license) = options.license_key {
            log::info!("Applying Warp+ license key...");
            update_license(&credentials, license).await?;
            credentials.license_key = license.clone();
        }
    }

    // Fetch full configuration (may contain updated client_id)
    let (config, updated_client_id) = get_config_with_client_id(&credentials).await?;

    // Update client_id if we got one from the config fetch
    if updated_client_id.is_some() {
        credentials.client_id = updated_client_id;
    }

    Ok((config, credentials))
}

/// Parse client_id from base64 string to [u8; 3].
fn parse_client_id(client_id_b64: Option<&str>) -> Result<Option<[u8; 3]>> {
    match client_id_b64 {
        Some(s) if !s.is_empty() => {
            let bytes = STANDARD
                .decode(s)
                .map_err(|e| Error::InvalidResponse(format!("Invalid client_id base64: {}", e)))?;
            if bytes.len() >= 3 {
                Ok(Some([bytes[0], bytes[1], bytes[2]]))
            } else {
                log::warn!(
                    "client_id has unexpected length {}, expected at least 3 bytes",
                    bytes.len()
                );
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

/// Get WireGuard configuration from existing credentials.
pub async fn get_config(credentials: &WarpCredentials) -> Result<WireGuardConfig> {
    let (config, _) = get_config_with_client_id(credentials).await?;
    Ok(config)
}

/// Get WireGuard configuration from existing credentials, also returning client_id if present.
async fn get_config_with_client_id(
    credentials: &WarpCredentials,
) -> Result<(WireGuardConfig, Option<[u8; 3]>)> {
    let client = create_client(Some(&credentials.access_token), None)?;

    log::info!(
        "Fetching WARP configuration for device {}...",
        credentials.device_id
    );

    let resp: GetSourceDeviceResponse = client
        .get(format!(
            "{}/{}/reg/{}",
            API_URL, API_VERSION, credentials.device_id
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let peer = resp
        .config
        .peers
        .first()
        .ok_or_else(|| Error::InvalidResponse("No peers in config".to_string()))?;

    // Decode peer public key
    let peer_public_key: [u8; 32] = STANDARD
        .decode(&peer.public_key)
        .map_err(|e| Error::InvalidKey(e.to_string()))?
        .try_into()
        .map_err(|_| Error::InvalidKey("Invalid key length".to_string()))?;

    // Parse tunnel IP (v4), stripping CIDR notation
    let tunnel_ip = resp
        .config
        .interface
        .addresses
        .v4
        .split('/')
        .next()
        .unwrap_or(&resp.config.interface.addresses.v4)
        .parse()
        .map_err(|_| Error::InvalidAddress(resp.config.interface.addresses.v4.clone()))?;

    // v0.2.0（warp-rust fork）：解析 v6 tunnel address。
    // Cloudflare WARP 给的格式是 "fd01:...:1c20/128"。
    let tunnel_ipv6 = if resp.config.interface.addresses.v6.is_empty() {
        None
    } else {
        let v6_str = resp.config.interface.addresses.v6.clone();
        let parsed: std::result::Result<std::net::Ipv6Addr, _> =
            v6_str.split('/').next().unwrap_or(&v6_str).parse();
        match parsed {
            Ok(addr) => {
                log::debug!("Parsed tunnel IPv6: {}", addr);
                Some(addr)
            }
            Err(e) => {
                log::warn!(
                    "Failed to parse tunnel IPv6 '{}': {}; falling back to v4-only",
                    v6_str,
                    e
                );
                None
            }
        }
    };

    // 保留 DNS 返回的全部 A/AAAA，并把 API v4/v6 追加为兜底。上层按
    // (IP, port) 尝试，而不是只在第一枚 IPv4 上轮换端口。
    let peer_endpoint_candidates = resolve_peer_endpoints(&peer.endpoint).await?;
    let peer_endpoint = peer_endpoint_candidates[0];

    // Parse client_id if present
    let client_id = parse_client_id(resp.config.client_id.as_deref())?;

    log::info!(
        "Configuration retrieved: tunnel_ip={}, tunnel_ipv6={:?}, endpoint={}, endpoint_candidates={}, client_id={:?}",
        tunnel_ip,
        tunnel_ipv6,
        peer_endpoint,
        peer_endpoint_candidates.len(),
        client_id.map(|id| format!("0x{:02x}{:02x}{:02x}", id[0], id[1], id[2]))
    );

    let config = WireGuardConfig {
        private_key: credentials.private_key,
        peer_public_key,
        peer_endpoint,
        peer_endpoint_candidates,
        tunnel_ip,
        tunnel_ipv6,
        preshared_key: None,
        keepalive_seconds: Some(25),
        mtu: None, // Use default MTU
        tcp_buffer_size: None,
    };

    Ok((config, client_id))
}

/// Update the license key on an existing registration.
pub async fn update_license(credentials: &WarpCredentials, license_key: &str) -> Result<()> {
    let client = create_client(Some(&credentials.access_token), None)?;

    let req = UpdateAccountRequest {
        license: license_key.to_string(),
    };

    client
        .put(format!(
            "{}/{}/reg/{}/account",
            API_URL, API_VERSION, credentials.device_id
        ))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;

    log::info!("License key updated successfully");

    Ok(())
}

// ============================================================================
// v0.4.5（warp-rust fork）：WARP peer endpoint 候选解析
// ============================================================================
//
// 设计目标：让 WG peer endpoint 跟随 Cloudflare DNS/Anycast 调度，并在某一
// ingress IP 路由不良时切到其它 A/AAAA/API 地址。流程：
//
//   1. lookup_host 收集全部 A/AAAA，按系统 resolver 顺序保留并去重。
//   2. 追加 API endpoint.v4/v6，端口以 endpoint.host 为准。
//   3. DNS 与 API 全部无有效地址才返回 InvalidEndpoint。
//
// parse_api_endpoint / merge_endpoint_candidates 是纯函数，便于覆盖格式与去重边界。

fn endpoint_port(endpoint: &Endpoint) -> u16 {
    endpoint
        .host
        .rsplit_once(':')
        .and_then(|(_, p)| p.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(2408)
}

fn push_unique(candidates: &mut Vec<SocketAddr>, candidate: SocketAddr) {
    if !candidates.contains(&candidate) {
        candidates.push(candidate);
    }
}

fn parse_api_endpoint(raw: &str, port: u16) -> Option<SocketAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(socket) = raw.parse::<SocketAddr>() {
        return Some(SocketAddr::new(socket.ip(), port));
    }
    raw.parse().ok().map(|ip| SocketAddr::new(ip, port))
}

fn merge_endpoint_candidates(
    dns_candidates: impl IntoIterator<Item = SocketAddr>,
    endpoint: &Endpoint,
) -> Result<Vec<SocketAddr>> {
    let mut candidates = Vec::new();
    for candidate in dns_candidates {
        push_unique(&mut candidates, candidate);
    }

    let port = endpoint_port(endpoint);
    if let Some(v4) = parse_api_endpoint(&endpoint.v4, port) {
        push_unique(&mut candidates, v4);
    }
    if let Some(v6) = parse_api_endpoint(&endpoint.v6, port) {
        push_unique(&mut candidates, v6);
    }

    if candidates.is_empty() {
        return Err(Error::InvalidEndpoint(format!(
            "DNS/API endpoint candidates empty: host='{}' v4='{}' v6='{}'",
            endpoint.host, endpoint.v4, endpoint.v6
        )));
    }
    Ok(candidates)
}

/// 异步解析全部 WARP peer endpoint：DNS A/AAAA 优先，API v4/v6 兜底。
async fn resolve_peer_endpoints(endpoint: &Endpoint) -> Result<Vec<SocketAddr>> {
    let host_str = endpoint.host.trim();
    let mut dns_candidates = Vec::new();
    match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(host_str)).await {
        Err(_) => {
            log::warn!(
                "WARP endpoint DNS '{}' timed out; using API v4/v6 fallbacks",
                host_str,
            );
        }
        Ok(Ok(iter)) => {
            for sa in iter {
                push_unique(&mut dns_candidates, sa);
            }
            if dns_candidates.is_empty() {
                log::warn!(
                    "WARP endpoint DNS '{}' returned no addresses; using API fallbacks",
                    host_str,
                );
            }
        }
        Ok(Err(e)) => {
            log::warn!(
                "WARP endpoint DNS '{}' failed: {}; using API v4/v6 fallbacks",
                host_str,
                e,
            );
        }
    }
    let candidates = merge_endpoint_candidates(dns_candidates, endpoint)?;
    log::info!(
        "WARP endpoint candidates for '{}': {:?}",
        host_str,
        candidates
    );
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str, v4: &str, v6: &str) -> Endpoint {
        Endpoint {
            host: host.into(),
            v4: v4.into(),
            v6: v6.into(),
        }
    }

    #[test]
    fn api_fallback_parses_v4_and_v6_with_host_port() {
        let candidates = merge_endpoint_candidates(
            [],
            &ep(
                "engage.cloudflareclient.com:2408",
                "162.159.192.7:0",
                "[2606:4700::7]:0",
            ),
        )
        .unwrap();
        assert_eq!(
            candidates,
            vec![
                "162.159.192.7:2408".parse().unwrap(),
                "[2606:4700::7]:2408".parse().unwrap()
            ]
        );
    }

    #[test]
    fn fallback_handles_bare_v4_no_port() {
        let candidates = merge_endpoint_candidates(
            [],
            &ep("engage.cloudflareclient.com:2408", "162.159.192.7", ""),
        )
        .unwrap();
        assert_eq!(candidates[0].to_string(), "162.159.192.7:2408");
    }

    #[test]
    fn fallback_handles_missing_host_port_defaults_2408() {
        let candidates = merge_endpoint_candidates(
            [],
            &ep("engage.cloudflareclient.com", "162.159.192.7:0", ""),
        )
        .unwrap();
        assert_eq!(candidates[0].port(), 2408);
    }

    #[test]
    fn fallback_rejects_when_dns_and_api_are_all_invalid() {
        let err = merge_endpoint_candidates(
            [],
            &ep("engage.cloudflareclient.com:2408", "not.an.ip:0", "bad-v6"),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("candidates empty"), "got: {msg}");
    }

    #[test]
    fn fallback_rejects_garbage_port_uses_default() {
        let candidates = merge_endpoint_candidates(
            [],
            &ep(
                "engage.cloudflareclient.com:not-a-port",
                "162.159.192.7:0",
                "",
            ),
        )
        .unwrap();
        assert_eq!(candidates[0].port(), 2408);
    }

    #[test]
    fn dns_and_api_candidates_are_ordered_and_deduplicated() {
        let dns = vec![
            "162.159.192.7:2408".parse().unwrap(),
            "[2606:4700::7]:2408".parse().unwrap(),
            "162.159.192.7:2408".parse().unwrap(),
        ];
        let candidates = merge_endpoint_candidates(
            dns,
            &ep(
                "engage.cloudflareclient.com:2408",
                "162.159.192.7:0",
                "[2606:4700::8]:0",
            ),
        )
        .unwrap();
        assert_eq!(
            candidates,
            vec![
                "162.159.192.7:2408".parse().unwrap(),
                "[2606:4700::7]:2408".parse().unwrap(),
                "[2606:4700::8]:2408".parse().unwrap()
            ]
        );
    }

    #[test]
    fn every_dns_address_is_retained() {
        let dns = (1..=20)
            .map(|last| format!("162.159.192.{last}:2408").parse().unwrap())
            .collect::<Vec<_>>();
        let candidates = merge_endpoint_candidates(
            dns.clone(),
            &ep(
                "engage.cloudflareclient.com:2408",
                "188.114.96.7:0",
                "[2606:4700::7]:0",
            ),
        )
        .unwrap();
        assert_eq!(&candidates[..dns.len()], dns.as_slice());
        assert_eq!(candidates.len(), dns.len() + 2);
    }
}
