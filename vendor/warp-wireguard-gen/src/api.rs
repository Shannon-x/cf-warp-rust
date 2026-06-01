//! Cloudflare WARP API client implementation.

use std::net::SocketAddr;
use std::sync::Arc;

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
    headers.insert("CF-Client-Version", CF_CLIENT_VERSION.parse().unwrap());
    headers.insert(
        reqwest::header::ACCEPT,
        "application/json; charset=UTF-8".parse().unwrap(),
    );

    if let Some(token) = auth_token {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
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
        .http1_only(); // No HTTP/2 to match official client behavior

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
        let parsed: std::result::Result<std::net::Ipv6Addr, _> = v6_str
            .split('/')
            .next()
            .unwrap_or(&v6_str)
            .parse();
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

    // v0.2.3（warp-rust fork）：优先 DNS 解析 peer.endpoint.host，让 Cloudflare
    // 自家的 DNS/Anycast 调度选当前最优 IP；失败时 fallback 到 API 返回的 v4。
    //
    // 旧实现「直接固定 API 返回的 v4 IP」的问题：
    //   · 这个 IP 24h 内被某条骨干网限速 / 误屏蔽时，无法切换
    //   · API 缓存的 IP 与 Cloudflare DNS 实际推荐的 IP 不一致时，命中差的那个
    //   · WARP endpoint 设计上就是给 DNS-driven 调度用的稳定入口
    let peer_endpoint = resolve_peer_endpoint(&peer.endpoint).await?;

    // Parse client_id if present
    let client_id = parse_client_id(resp.config.client_id.as_deref())?;

    log::info!(
        "Configuration retrieved: tunnel_ip={}, tunnel_ipv6={:?}, endpoint={}, client_id={:?}",
        tunnel_ip,
        tunnel_ipv6,
        peer_endpoint,
        client_id.map(|id| format!("0x{:02x}{:02x}{:02x}", id[0], id[1], id[2]))
    );

    let config = WireGuardConfig {
        private_key: credentials.private_key,
        peer_public_key,
        peer_endpoint,
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
// v0.2.3（warp-rust fork）：WARP peer endpoint 解析
// ============================================================================
//
// 设计目标：让 WG peer endpoint 跟随 Cloudflare DNS/Anycast 调度，而不是把
// API 返回的某一个 IPv4 IP 写死。流程：
//
//   1. 先用 tokio::net::lookup_host(host) 解析 "engage.cloudflareclient.com:2408"
//      返回的第一个 IPv4 SocketAddr。这是 happy path，让 Cloudflare 自家 DNS
//      把请求引到当前最优入口（不同地区不同 IP）。
//   2. DNS 失败、无 v4 记录、或返回空时，fallback 到 API 响应里 peer.endpoint.v4
//      并配合 host 字段提取的端口。保留兼容性，离线/隔离环境也能跑通。
//   3. fallback 自己解析失败（v4 文本非法）→ 显式 Error::InvalidEndpoint，
//      不 unwrap、不 panic。
//
// fallback_endpoint 拆成纯函数（无 IO）方便加单元测试覆盖各种格式边界。

/// 异步解析 WARP peer endpoint：DNS 优先，失败 fallback 到 API 提供的 v4。
async fn resolve_peer_endpoint(endpoint: &Endpoint) -> Result<SocketAddr> {
    let host_str = endpoint.host.trim();
    match tokio::net::lookup_host(host_str).await {
        Ok(iter) => {
            for sa in iter {
                if let SocketAddr::V4(_) = sa {
                    log::info!(
                        "WARP endpoint via DNS: '{}' -> {}",
                        host_str,
                        sa,
                    );
                    return Ok(sa);
                }
            }
            log::warn!(
                "WARP endpoint DNS '{}' returned no IPv4; fallback to API v4='{}'",
                host_str,
                endpoint.v4,
            );
        }
        Err(e) => {
            log::warn!(
                "WARP endpoint DNS '{}' failed: {}; fallback to API v4='{}'",
                host_str,
                e,
                endpoint.v4,
            );
        }
    }
    fallback_endpoint(endpoint)
}

/// 不做 IO 的 fallback 解析：从 peer.endpoint.v4 取 IP，从 peer.endpoint.host
/// 取端口，组装出 SocketAddr。两种字段都可能格式异常，全部走 Result。
fn fallback_endpoint(endpoint: &Endpoint) -> Result<SocketAddr> {
    // v4 字段通常是 "162.159.x.x:0"，去掉端口部分（:0 没意义）
    let v4_ip_str = endpoint
        .v4
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(endpoint.v4.as_str())
        .trim();

    // host 字段通常是 "engage.cloudflareclient.com:2408"
    let port = endpoint
        .host
        .rsplit_once(':')
        .and_then(|(_, p)| p.trim().parse::<u16>().ok())
        .unwrap_or(2408);

    let assembled = format!("{}:{}", v4_ip_str, port);
    assembled.parse::<SocketAddr>().map_err(|_| {
        Error::InvalidEndpoint(format!(
            "fallback parse failed: v4='{}' host='{}' assembled='{}'",
            endpoint.v4, endpoint.host, assembled
        ))
    })
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
    fn fallback_parses_v4_with_zero_port_suffix() {
        // 典型 WARP API 响应格式：v4 带 :0 后缀
        let sa = fallback_endpoint(&ep(
            "engage.cloudflareclient.com:2408",
            "162.159.192.7:0",
            "[2606:4700::]:2408",
        ))
        .unwrap();
        assert_eq!(sa.to_string(), "162.159.192.7:2408");
    }

    #[test]
    fn fallback_handles_bare_v4_no_port() {
        // 防御：v4 字段如果就是裸 IP 没冒号
        let sa = fallback_endpoint(&ep(
            "engage.cloudflareclient.com:2408",
            "162.159.192.7",
            "",
        ))
        .unwrap();
        assert_eq!(sa.to_string(), "162.159.192.7:2408");
    }

    #[test]
    fn fallback_handles_missing_host_port_defaults_2408() {
        // host 没端口（极少见）→ 默认 2408（WARP 标准）
        let sa = fallback_endpoint(&ep(
            "engage.cloudflareclient.com",
            "162.159.192.7:0",
            "",
        ))
        .unwrap();
        assert_eq!(sa.port(), 2408);
    }

    #[test]
    fn fallback_rejects_invalid_v4_text() {
        // 非法 IPv4 文本 → Err，不 panic
        let err = fallback_endpoint(&ep(
            "engage.cloudflareclient.com:2408",
            "not.an.ip:0",
            "",
        ))
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("fallback parse failed"), "got: {msg}");
    }

    #[test]
    fn fallback_rejects_garbage_port_uses_default() {
        // host 端口非数字 → 走默认 2408（容忍）
        let sa = fallback_endpoint(&ep(
            "engage.cloudflareclient.com:not-a-port",
            "162.159.192.7:0",
            "",
        ))
        .unwrap();
        assert_eq!(sa.port(), 2408);
    }
}
