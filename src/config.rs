//! 配置 schema，通过 figment 按 默认值 → config.toml → 环境变量 三层叠加。
//!
//! 即便 M1 阶段只用到其中一部分，schema 也是完整写出来的；M2/M3 直接复用，
//! 不需要再回头改结构体。

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub warp: WarpConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub recovery: RecoveryConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub hot_reload: HotReloadConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:1080".parse().unwrap(),
            auth: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Compact,
    Json,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info,warp_rust=debug,wireguard_netstack=info".to_string(),
            format: LogFormat::Pretty,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpConfig {
    pub data_dir: PathBuf,
    pub device_model: String,
    #[serde(default)]
    pub license_key: Option<String>,
    #[serde(with = "humantime_serde", default = "default_refresh_interval")]
    pub refresh_interval: Duration,
    #[serde(with = "humantime_serde", default = "default_register_cooldown")]
    pub register_cooldown: Duration,
}

fn default_refresh_interval() -> Duration {
    Duration::from_secs(86_400)
}

fn default_register_cooldown() -> Duration {
    Duration::from_secs(600)
}

impl Default for WarpConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            device_model: "warp-rust".to_string(),
            license_key: None,
            refresh_interval: default_refresh_interval(),
            register_cooldown: default_register_cooldown(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(8),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    pub reconnect_after: u8,
    pub rebuild_config_after: u8,
    pub reregister_after: u8,
    pub rotate_identity_after: u8,
    #[serde(with = "humantime_serde")]
    pub backoff_min: Duration,
    #[serde(with = "humantime_serde")]
    pub backoff_max: Duration,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            reconnect_after: 1,
            rebuild_config_after: 3,
            reregister_after: 5,
            rotate_identity_after: 10,
            backoff_min: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1:9090".parse().unwrap(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HotReloadConfig {
    #[serde(default)]
    pub enabled: bool,
}

impl Config {
    /// 按 默认值 → `config.toml`（存在时）→ `WARP_RUST_*` 环境变量 三层叠加加载。
    pub fn load(path: Option<&Path>) -> Result<Self, figment::Error> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(p) = path {
            if p.exists() {
                fig = fig.merge(Toml::file(p));
            }
        }
        fig.merge(Env::prefixed("WARP_RUST_").split("__")).extract()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            logging: LoggingConfig::default(),
            warp: WarpConfig::default(),
            health: HealthConfig::default(),
            recovery: RecoveryConfig::default(),
            metrics: MetricsConfig::default(),
            hot_reload: HotReloadConfig::default(),
        }
    }
}
