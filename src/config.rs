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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub dns: DnsConfig,
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
    /// WireGuard 接口 MTU。Cloudflare WARP 推荐 1280，更大可调到 1420（标准 WG）。
    /// 默认 1280：含 80 字节安全余量，绝大多数线路都能通过。
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_refresh_interval() -> Duration {
    Duration::from_secs(86_400)
}

fn default_register_cooldown() -> Duration {
    Duration::from_secs(600)
}

fn default_mtu() -> u16 {
    1280
}

impl Default for WarpConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            device_model: "warp-rust".to_string(),
            license_key: None,
            refresh_interval: default_refresh_interval(),
            register_cooldown: default_register_cooldown(),
            mtu: default_mtu(),
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

/// DoS 防护与资源限制
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// 同时在飞 SOCKS5 连接上限；满后新连接立刻关闭并记 metric
    pub max_concurrent_connections: usize,
    /// SOCKS5 握手（含 read_command）超时；超时即关
    #[serde(with = "humantime_serde")]
    pub handshake_timeout: Duration,
    /// 双向 relay 的 idle 超时；上下行都无数据传输到达时关连接
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// 鉴权失败后延迟，缓解暴破
    #[serde(with = "humantime_serde")]
    pub auth_fail_sleep: Duration,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_connections: 1024,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            auth_fail_sleep: Duration::from_secs(1),
        }
    }
}

/// DNS 解析策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// "system"（默认，宿主 DNS，最快但泄漏域名）|
    /// "tunnel"（隧道内 UDP 拨 servers，更隐私，多一跳 RTT；带缓存后几乎无感）
    pub mode: DnsMode,
    /// mode = "tunnel" 时使用的 DNS server 列表（IPv4:port）
    pub servers: Vec<SocketAddr>,
    /// 单次 DNS 查询超时
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// LRU 缓存 TTL；命中跳过 DNS 查询
    #[serde(with = "humantime_serde")]
    pub cache_ttl: Duration,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    System,
    Tunnel,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: DnsMode::System,
            servers: vec!["1.1.1.1:53".parse().unwrap(), "1.0.0.1:53".parse().unwrap()],
            timeout: Duration::from_secs(3),
            cache_ttl: Duration::from_secs(60),
        }
    }
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

    /// 启动前安全校验：拒绝公网（非 loopback）+ 无鉴权组合。
    /// 用户若清楚自己在做什么，可设环境变量 `WARP_RUST_ALLOW_OPEN_PROXY=1` 跳过。
    pub fn validate(&self) -> Result<(), String> {
        let ip = self.server.bind.ip();
        if !ip.is_loopback() && self.server.auth.is_none() {
            if std::env::var("WARP_RUST_ALLOW_OPEN_PROXY").ok().as_deref() == Some("1") {
                tracing::warn!(
                    bind = %self.server.bind,
                    "WARP_RUST_ALLOW_OPEN_PROXY=1：跳过开放代理校验（你已显式接受高风险）"
                );
                return Ok(());
            }
            return Err(format!(
                "拒绝启动：server.bind = {} 不是 loopback，但 [server.auth] 为空。\n  \
                 这等于把无鉴权的 SOCKS5 暴露给互联网。\n  \
                 · 改回本机：把 bind 改成 127.0.0.1:<port>\n  \
                 · 启用鉴权：在 config.toml 加 [server.auth] username/password（≥16 位强密码）\n  \
                 · 显式覆盖（不推荐）：设置环境变量 WARP_RUST_ALLOW_OPEN_PROXY=1",
                self.server.bind,
            ));
        }
        // metrics 端口同样校验：含运营信息，公网暴露不可（无 metrics 鉴权机制）
        let m = self.metrics.bind.ip();
        if self.metrics.enabled && !m.is_loopback() {
            tracing::warn!(
                bind = %self.metrics.bind,
                "metrics 监听非 loopback；建议改为 127.0.0.1:9090 或通过反代/SSH 转发访问"
            );
        }
        // 鉴权字段健全性
        if let Some(auth) = &self.server.auth {
            if auth.username.is_empty() || auth.password.is_empty() {
                return Err("[server.auth] username 或 password 不能为空".into());
            }
            if auth.password.len() < 8 {
                return Err(format!(
                    "[server.auth] password 长度仅 {}，至少 8 位；推荐 ≥16 位强密码",
                    auth.password.len()
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(bind: &str, auth: Option<(&str, &str)>) -> Config {
        let mut c = Config::default();
        c.server.bind = bind.parse().unwrap();
        c.server.auth = auth.map(|(u, p)| AuthConfig {
            username: u.into(),
            password: p.into(),
        });
        c
    }

    #[test]
    fn validate_loopback_no_auth_ok() {
        assert!(cfg_with("127.0.0.1:1080", None).validate().is_ok());
    }

    #[test]
    fn validate_public_no_auth_rejected() {
        let err = cfg_with("0.0.0.0:1080", None).validate().unwrap_err();
        assert!(err.contains("拒绝启动"));
    }

    #[test]
    fn validate_public_with_auth_ok() {
        assert!(cfg_with("0.0.0.0:1080", Some(("u", "MyStrongPass123!")))
            .validate()
            .is_ok());
    }

    #[test]
    fn validate_weak_password_rejected() {
        let err = cfg_with("0.0.0.0:1080", Some(("u", "short")))
            .validate()
            .unwrap_err();
        assert!(err.contains("password"));
    }
}
