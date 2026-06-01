//! Error types for the warp-wireguard-gen crate.

use thiserror::Error;

/// Result type alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when interacting with the Cloudflare WARP API.
#[derive(Debug, Error)]
pub enum Error {
    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// API returned an error response.
    #[error("API error: {message} (code: {code})")]
    Api {
        /// Error code from the API.
        code: i32,
        /// Error message from the API.
        message: String,
    },

    /// API response was invalid or missing expected fields.
    #[error("Invalid API response: {0}")]
    InvalidResponse(String),

    /// Failed to parse endpoint address.
    #[error("Failed to parse endpoint: {0}")]
    InvalidEndpoint(String),

    /// Failed to parse IP address.
    #[error("Failed to parse IP address: {0}")]
    InvalidAddress(String),

    /// Invalid base64-encoded key.
    #[error("Invalid base64 key: {0}")]
    InvalidKey(String),

    /// TLS configuration error.
    #[error("TLS configuration error: {0}")]
    Tls(String),

    /// DNS resolution failed.
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    /// Teams enrollment JWT token is invalid or expired.
    ///
    /// The JWT token obtained from the Cloudflare Access portal is ephemeral
    /// and expires shortly after being issued. Re-authenticate and obtain
    /// a fresh token.
    #[error("Teams enrollment failed: {0}")]
    TeamsEnrollment(String),
}
