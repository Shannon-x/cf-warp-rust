//! API request and response types for the Cloudflare WARP API.

use serde::{Deserialize, Serialize};

/// Request body for device registration.
///
/// This struct is used for both consumer WARP and Cloudflare for Teams enrollment.
/// For Teams enrollment, the `serial_number` and `name` fields can be populated,
/// and the JWT assertion is sent via a separate HTTP header.
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    /// FCM token (empty for non-Android clients).
    pub fcm_token: String,
    /// Installation ID (empty for non-Android clients).
    pub install_id: String,
    /// Base64-encoded public key.
    pub key: String,
    /// Locale string (e.g., "en_US").
    pub locale: String,
    /// Device model name.
    pub model: String,
    /// TOS acceptance timestamp (RFC3339).
    ///
    /// Note: For Teams enrollment, this field is omitted (not sent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos: Option<String>,
    /// Device type (e.g., "Android").
    ///
    /// Note: For Teams enrollment, this field is omitted (not sent).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    /// Device serial number (used for Teams enrollment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Device name (used for Teams enrollment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Response from device registration.
#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    /// Unique device identifier.
    pub id: String,
    /// Authentication token for subsequent requests.
    pub token: String,
    /// Account information.
    pub account: Account,
    /// WireGuard configuration.
    pub config: Config,
}

/// Account information.
#[derive(Debug, Deserialize)]
pub struct Account {
    /// Account license key (may be absent for Teams enrollment).
    #[serde(default)]
    pub license: String,
    /// Whether the account has Warp+ enabled.
    #[serde(default)]
    pub warp_plus: bool,
}

/// WireGuard configuration from the API.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Interface configuration.
    pub interface: Interface,
    /// Peer configurations.
    pub peers: Vec<Peer>,
    /// Client ID (base64-encoded, used for WARP reserved field).
    ///
    /// This is also referred to as "reserved key" as the client ID
    /// is put in the reserved field in the WireGuard header.
    /// Used by Cloudflare to identify the device/account.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Interface configuration.
#[derive(Debug, Deserialize)]
pub struct Interface {
    /// Assigned IP addresses.
    pub addresses: NetworkAddress,
}

/// Network addresses (IPv4 and IPv6).
#[derive(Debug, Deserialize)]
pub struct NetworkAddress {
    /// IPv4 address with CIDR notation.
    pub v4: String,
    /// IPv6 address with CIDR notation.
    pub v6: String,
}

/// Peer configuration.
#[derive(Debug, Deserialize)]
pub struct Peer {
    /// Base64-encoded public key.
    pub public_key: String,
    /// Endpoint information.
    pub endpoint: Endpoint,
}

/// Endpoint information.
#[derive(Debug, Deserialize)]
pub struct Endpoint {
    /// Hostname with port (e.g., "engage.cloudflareclient.com:2408").
    pub host: String,
    /// IPv4 address.
    pub v4: String,
    /// IPv6 address.
    pub v6: String,
}

/// Response from GetSourceDevice endpoint.
#[derive(Debug, Deserialize)]
pub struct GetSourceDeviceResponse {
    /// WireGuard configuration.
    pub config: Config,
    /// Account information.
    pub account: Account,
}

/// Request body for updating account license.
#[derive(Debug, Serialize)]
pub struct UpdateAccountRequest {
    /// New license key.
    pub license: String,
}
