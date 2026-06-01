//! Cloudflare WARP API client implementation.

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

    // Use the direct IPv4 endpoint from the API response
    // (Don't resolve the hostname - it may return a different/wrong IP)
    // The v4 field contains "IP:0" format, so we strip the port and use the one from host field
    // (or default to 2408 which is WARP's standard port)
    let endpoint_ip = peer.endpoint.v4
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(&peer.endpoint.v4);
    
    let port = peer.endpoint.host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(2408); // Default WARP port
    
    let peer_endpoint = format!("{}:{}", endpoint_ip, port)
        .parse()
        .map_err(|_| Error::InvalidEndpoint(peer.endpoint.v4.clone()))?;

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