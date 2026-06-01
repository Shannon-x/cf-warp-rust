//! Generate WireGuard configurations by registering with Cloudflare WARP.
//!
//! This crate provides functionality to:
//! - Register a new device with Cloudflare WARP (consumer)
//! - Register a device with Cloudflare for Teams / Zero Trust
//! - Retrieve WireGuard configuration for connecting through WARP
//! - Optionally apply a Warp+ license key
//!
//! # Example
//!
//! ```no_run
//! use warp_wireguard_gen::{register, RegistrationOptions};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Register with default options (consumer WARP)
//!     let (config, credentials) = register(RegistrationOptions::default()).await?;
//!     
//!     // Use config with wireguard-netstack...
//!     // Optionally save credentials for reuse...
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Cloudflare for Teams (Zero Trust) Enrollment
//!
//! To enroll with Cloudflare for Teams:
//!
//! 1. Visit `https://<team-name>.cloudflareaccess.com/warp`
//! 2. Authenticate as you would with the official WARP client
//! 3. Extract the JWT token from the page source or use browser console:
//!    ```js
//!    console.log(document.querySelector("meta[http-equiv='refresh']").content.split("=")[2])
//!    ```
//! 4. Pass the JWT token via [`TeamsEnrollment`] in [`RegistrationOptions`]
//!
//! ```no_run
//! use warp_wireguard_gen::{register, RegistrationOptions, TeamsEnrollment};
//!
//! # async fn example() -> warp_wireguard_gen::Result<()> {
//! let (config, credentials) = register(RegistrationOptions {
//!     device_model: "PC".to_string(),
//!     license_key: None,
//!     teams: Some(TeamsEnrollment {
//!         jwt_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...".to_string(),
//!         device_name: Some("My Device".to_string()),
//!         serial_number: None,
//!     }),
//! }).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Flags
//!
//! - `serde`: Enables `Serialize` and `Deserialize` for `WarpCredentials`,
//!   allowing easy persistence to JSON, TOML, etc.
//!
//! # Credential Persistence
//!
//! The [`WarpCredentials`] struct returned by [`register`] contains all the
//! information needed to reconnect without re-registering. Enable the `serde`
//! feature to serialize credentials for storage.
//!
//! ```no_run
//! # #[cfg(feature = "serde")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use warp_wireguard_gen::{register, get_config, RegistrationOptions, WarpCredentials};
//!
//! // First run: register and save credentials
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let (config, credentials) = register(RegistrationOptions::default()).await?;
//! let json = serde_json::to_string_pretty(&credentials)?;
//! std::fs::write("warp-credentials.json", &json)?;
//!
//! // Later: load credentials and get fresh config
//! let json = std::fs::read_to_string("warp-credentials.json")?;
//! let credentials: WarpCredentials = serde_json::from_str(&json)?;
//! let config = get_config(&credentials).await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # });
//! # Ok(())
//! # }
//! ```

pub mod api;
pub mod error;
pub mod keys;
pub mod types;

pub use error::{Error, Result};

use base64::{engine::general_purpose::STANDARD, Engine};
use wireguard_netstack::WireGuardConfig;

/// Options for registering a new WARP device.
#[derive(Debug, Clone)]
pub struct RegistrationOptions {
    /// Device model name displayed in the 1.1.1.1 app.
    ///
    /// Default: `"PC"`
    pub device_model: String,

    /// Optional Warp+ license key.
    ///
    /// Must be purchased through the official 1.1.1.1 app.
    /// Keys obtained by other means (including referrals) will not work.
    ///
    /// Note: This is not applicable for Teams enrollment.
    pub license_key: Option<String>,

    /// Cloudflare for Teams enrollment options.
    ///
    /// When set, the registration will use Cloudflare Zero Trust (formerly
    /// Cloudflare for Teams) enrollment instead of consumer WARP.
    pub teams: Option<TeamsEnrollment>,
}

/// Cloudflare for Teams (Zero Trust) enrollment configuration.
///
/// To obtain the JWT token:
/// 1. Visit `https://<team-name>.cloudflareaccess.com/warp`
/// 2. Authenticate as you would with the official WARP client
/// 3. Extract the JWT token from the page source or use browser console:
///    ```js
///    console.log(document.querySelector("meta[http-equiv='refresh']").content.split("=")[2])
///    ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TeamsEnrollment {
    /// JWT token obtained from the Teams authentication portal.
    ///
    /// This is an ephemeral token that expires shortly after being issued.
    pub jwt_token: String,

    /// Optional device name shown in the Zero Trust dashboard.
    pub device_name: Option<String>,

    /// Optional device serial number.
    pub serial_number: Option<String>,
}

impl Default for RegistrationOptions {
    fn default() -> Self {
        Self {
            device_model: "PC".to_string(),
            license_key: None,
            teams: None,
        }
    }
}

/// Credentials for an existing WARP device registration.
///
/// Store these to avoid re-registering on each use. Use [`get_config`] to
/// obtain a fresh [`WireGuardConfig`] from existing credentials.
///
/// Enable the `serde` feature for JSON/TOML serialization support.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WarpCredentials {
    /// Unique device identifier assigned by Cloudflare.
    pub device_id: String,

    /// Bearer token for API authentication.
    pub access_token: String,

    /// WireGuard private key (32 bytes).
    #[cfg_attr(feature = "serde", serde(with = "base64_serde"))]
    pub private_key: [u8; 32],

    /// Account license key.
    pub license_key: String,

    /// Client ID (3 bytes) for the WARP reserved field.
    ///
    /// This is put in the reserved field in the WireGuard header and is used
    /// by Cloudflare to identify the device/account. This is required for
    /// proper routing, especially with Cloudflare for Teams.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "base64_opt_serde"
        )
    )]
    pub client_id: Option<[u8; 3]>,

    /// Whether this is a Cloudflare for Teams (Zero Trust) enrollment.
    #[cfg_attr(feature = "serde", serde(default))]
    pub is_teams: bool,
}

/// Serde helper module for base64-encoding the private key.
#[cfg(feature = "serde")]
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length, expected 32 bytes"))
    }
}

/// Serde helper module for base64-encoding the optional client_id.
#[cfg(feature = "serde")]
mod base64_opt_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<[u8; 3]>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 3]>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => {
                let bytes = STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?;
                let arr: [u8; 3] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("invalid client_id length, expected 3 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

impl WarpCredentials {
    /// Get the private key as a base64-encoded string.
    pub fn private_key_base64(&self) -> String {
        STANDARD.encode(self.private_key)
    }

    /// Get the client ID as a base64-encoded string.
    pub fn client_id_base64(&self) -> Option<String> {
        self.client_id.map(|id| STANDARD.encode(id))
    }

    /// Get the client ID as a hex string (e.g., "0xaabbcc").
    pub fn client_id_hex(&self) -> Option<String> {
        self.client_id
            .map(|id| format!("0x{:02x}{:02x}{:02x}", id[0], id[1], id[2]))
    }

    /// Get the client ID as decimal bytes (e.g., "[170, 187, 204]").
    pub fn client_id_decimal(&self) -> Option<[u8; 3]> {
        self.client_id
    }
}

/// Register a new device with Cloudflare WARP and get a WireGuard configuration.
///
/// This creates a new device registration with Cloudflare's WARP service and
/// returns both the WireGuard configuration and credentials for future use.
///
/// Supports both consumer WARP and Cloudflare for Teams (Zero Trust) enrollment.
///
/// # Arguments
///
/// * `options` - Registration options including device model and optional license key.
///
/// # Returns
///
/// A tuple of `(WireGuardConfig, WarpCredentials)` on success.
///
/// # Example
///
/// ```no_run
/// use warp_wireguard_gen::{register, RegistrationOptions, TeamsEnrollment};
///
/// # async fn example() -> warp_wireguard_gen::Result<()> {
/// // Basic registration (consumer WARP)
/// let (config, creds) = register(RegistrationOptions::default()).await?;
///
/// // With custom device name
/// let (config, creds) = register(RegistrationOptions {
///     device_model: "MyApp/1.0".to_string(),
///     license_key: None,
///     teams: None,
/// }).await?;
///
/// // With Warp+ license
/// let (config, creds) = register(RegistrationOptions {
///     device_model: "PC".to_string(),
///     license_key: Some("xxxxxxxx-xxxxxxxx-xxxxxxxx".to_string()),
///     teams: None,
/// }).await?;
///
/// // Cloudflare for Teams (Zero Trust) enrollment
/// let (config, creds) = register(RegistrationOptions {
///     device_model: "PC".to_string(),
///     license_key: None,
///     teams: Some(TeamsEnrollment {
///         jwt_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...".to_string(),
///         device_name: Some("My Device".to_string()),
///         serial_number: None,
///     }),
/// }).await?;
/// # Ok(())
/// # }
/// ```
pub async fn register(options: RegistrationOptions) -> Result<(WireGuardConfig, WarpCredentials)> {
    api::register(options).await
}

/// Get a WireGuard configuration using existing credentials.
///
/// Use this to refresh the configuration without creating a new registration.
/// This is useful when you have saved credentials from a previous [`register`] call.
///
/// # Arguments
///
/// * `credentials` - Previously obtained credentials from [`register`].
///
/// # Example
///
/// ```no_run
/// use warp_wireguard_gen::{get_config, WarpCredentials};
///
/// # async fn example(credentials: &WarpCredentials) -> warp_wireguard_gen::Result<()> {
/// let config = get_config(credentials).await?;
/// // Use config with wireguard-netstack...
/// # Ok(())
/// # }
/// ```
pub async fn get_config(credentials: &WarpCredentials) -> Result<WireGuardConfig> {
    api::get_config(credentials).await
}

/// Update the license key on an existing registration.
///
/// Use this to bind a Warp+ subscription to an existing device.
///
/// # Arguments
///
/// * `credentials` - Existing device credentials.
/// * `license_key` - Warp+ license key from the 1.1.1.1 app.
///
/// # Note
///
/// Only subscriptions purchased directly from the official 1.1.1.1 app are
/// supported. Keys obtained by other means (including referrals) will not work.
///
/// # Example
///
/// ```no_run
/// use warp_wireguard_gen::{update_license, WarpCredentials};
///
/// # async fn example(credentials: &WarpCredentials) -> warp_wireguard_gen::Result<()> {
/// update_license(credentials, "xxxxxxxx-xxxxxxxx-xxxxxxxx").await?;
/// # Ok(())
/// # }
/// ```
pub async fn update_license(credentials: &WarpCredentials, license_key: &str) -> Result<()> {
    api::update_license(credentials, license_key).await
}

/// Generate a new X25519 keypair.
///
/// This is exposed for advanced use cases where you want to provide your own key
/// during registration. Most users should use [`register`] which generates keys automatically.
///
/// # Returns
///
/// A tuple of `(private_key, public_key)` as 32-byte arrays.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    keys::generate_keypair()
}
