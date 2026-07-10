//! 配置 schema，通过 figment 按 默认值 → config.toml → 环境变量 三层叠加。
//!
//! 即便 M1 阶段只用到其中一部分，schema 也是完整写出来的；M2/M3 直接复用，
//! 不需要再回头改结构体。

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use metrics::counter;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::metrics::{M_CONTAINER_OPEN_PROXY_WARN, M_OPEN_PROXY_ALLOWED};

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
            level: "warn,warp_rust=info,wireguard_netstack=warn".to_string(),
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
    /// WireGuard 隧道接口 MTU（隧道内层可承载的最大 IP 包）。
    ///
    /// v0.4.2 起默认 **1280**——这是 IPv6 的最小 MTU，最保守：无论底层路径 MTU
    /// 多小（VPS 常见自带隧道封装、PPPoE、GRE，实际路径 MTU 常 <1500），1280 的
    /// 内层包加上 WireGuard 封装后（约 +60 字节，已含外层 IPv4+UDP 头）通常仍
    /// ≤1340，不会因超过路径 MTU 而被丢或分片。wgcf 默认也是 1280。
    ///
    /// 说明（避免误导）：Cloudflare 官方客户端用更大的值（约 1381），带宽敏感
    /// 且确认路径 MTU 足够（如物理机 1500）时可上调；范围 576..=1420。
    /// 注意：MTU 只影响“满载大包/传输阶段”，对 SYN 这类小包的建连超时通常无效。
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// smoltcp TCP socket 的单向 buffer 大小。实际每条 TCP 连接约占用 2 倍该值。
    #[serde(default = "default_tcp_buffer_size")]
    pub tcp_buffer_size: usize,
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

fn default_tcp_buffer_size() -> usize {
    256 * 1024
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
            tcp_buffer_size: default_tcp_buffer_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// 从隧道内拨号的独立目标。包含 Cloudflare 内部与外部网络，避免只探测
    /// 1.1.1.1 时把“隧道握手活着但公网出口坏了”误判为健康。
    #[serde(default = "default_health_targets")]
    pub targets: Vec<SocketAddr>,
    /// 一轮至少成功多少个目标才算健康。
    #[serde(default = "default_health_min_successes")]
    pub min_successes: usize,
}

fn default_health_targets() -> Vec<SocketAddr> {
    ["1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:53"]
        .into_iter()
        .map(|value| value.parse().expect("static health target"))
        .collect()
}

fn default_health_min_successes() -> usize {
    2
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(8),
            targets: default_health_targets(),
            min_successes: default_health_min_successes(),
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
    /// 同时处于 DNS/上游 TCP 建连阶段的请求上限。失败线路上的拨号会持有
    /// smoltcp socket RX/TX buffer，必须单独限流，避免重试风暴放大内存占用。
    #[serde(default = "default_max_pending_dials")]
    pub max_pending_dials: usize,
    /// SOCKS5 握手（含 read_command）超时；超时即关
    #[serde(with = "humantime_serde")]
    pub handshake_timeout: Duration,
    /// 从开始拨第一个候选到整体失败的总时限，覆盖所有 Happy Eyeballs 尝试。
    #[serde(with = "humantime_serde", default = "default_connect_timeout")]
    pub connect_timeout: Duration,
    /// 相邻候选的错峰启动间隔。
    #[serde(with = "humantime_serde", default = "default_happy_eyeballs_delay")]
    pub happy_eyeballs_delay: Duration,
    /// 单个目标最多尝试多少条 DNS 候选，防止恶意响应放大资源占用。
    #[serde(default = "default_max_dial_candidates")]
    pub max_dial_candidates: usize,
    /// 同一客户端拨号同时在飞的候选上限。
    #[serde(default = "default_max_parallel_dials")]
    pub max_parallel_dials: usize,
    /// 双向 relay 的 idle 超时；上下行都无数据传输到达时关连接
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// SOCKS TCP relay 每次读写使用的 buffer 大小。
    #[serde(default = "default_relay_buffer_size")]
    pub relay_buffer_size: usize,
    /// 鉴权失败后延迟，缓解暴破
    #[serde(with = "humantime_serde")]
    pub auth_fail_sleep: Duration,
    /// v0.3.2：双向 relay 中一侧退出后，给对端的「优雅退出」窗口；超时则 abort。
    /// 默认 500ms（对端正常会在毫秒级响应 CancellationToken + shutdown，grace 只是兜底）。
    #[serde(with = "humantime_serde", default = "default_relay_close_grace")]
    pub relay_close_grace: Duration,
}

fn default_relay_buffer_size() -> usize {
    64 * 1024
}

fn default_max_pending_dials() -> usize {
    128
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(12)
}

fn default_happy_eyeballs_delay() -> Duration {
    Duration::from_millis(200)
}

fn default_max_dial_candidates() -> usize {
    8
}

fn default_max_parallel_dials() -> usize {
    2
}

fn default_relay_close_grace() -> Duration {
    Duration::from_millis(500)
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_connections: 1024,
            max_pending_dials: default_max_pending_dials(),
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: default_connect_timeout(),
            happy_eyeballs_delay: default_happy_eyeballs_delay(),
            max_dial_candidates: default_max_dial_candidates(),
            max_parallel_dials: default_max_parallel_dials(),
            idle_timeout: Duration::from_secs(300),
            relay_buffer_size: default_relay_buffer_size(),
            auth_fail_sleep: Duration::from_secs(1),
            relay_close_grace: default_relay_close_grace(),
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
    /// 有界缓存 TTL；命中跳过 DNS 查询
    #[serde(with = "humantime_serde")]
    pub cache_ttl: Duration,
    /// Negative cache TTL：解析失败（NXDOMAIN / 超时 / 无该 qtype 记录）后的短暂缓存
    /// 时间。防止失败域名被反复打 DNS。建议很短（默认 5s），故意失败的客户端最多
    /// 5s 后能恢复。
    #[serde(with = "humantime_serde", default = "default_dns_negative_ttl")]
    pub negative_ttl: Duration,
    /// DNS 缓存条目硬上限，避免客户端用随机域名让 HashMap 无界增长。
    #[serde(default = "default_dns_max_cache_entries")]
    pub max_cache_entries: usize,
}

fn default_dns_negative_ttl() -> Duration {
    Duration::from_secs(5)
}

fn default_dns_max_cache_entries() -> usize {
    4096
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
            negative_ttl: default_dns_negative_ttl(),
            max_cache_entries: default_dns_max_cache_entries(),
        }
    }
}

impl Config {
    /// 按 默认值 → `config.toml`（存在时）→ `WARP_RUST_*` 环境变量 三层叠加加载。
    ///
    /// 返回 `crate::error::Result<Self>` 而非 `Result<Self, figment::Error>`：
    ///   1) figment::Error 大小 208 B，直接当 Err 类型会让本函数签名触发
    ///      clippy::result_large_err（默认阈值 128 B），与 Error::Figment 是否 Box
    ///      无关；
    ///   2) 不再向 caller 泄漏配置后端实现细节；
    ///   3) main.rs / config_watch.rs 里原本就是 `?` 立刻转 crate Error，所以
    ///      caller 端零改动、行为不变。
    pub fn load(path: Option<&Path>) -> crate::error::Result<Self> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(p) = path {
            if p.exists() {
                fig = fig.merge(Toml::file(p));
            }
        }
        Ok(fig
            .merge(Env::prefixed("WARP_RUST_").split("__"))
            .extract()?)
    }

    /// 启动前安全校验：拒绝公网（非 loopback）+ 无鉴权组合。
    /// 用户若清楚自己在做什么，可设环境变量 `WARP_RUST_ALLOW_OPEN_PROXY=1` 跳过。
    ///
    /// v0.3.2 起，容器内 `0.0.0.0` 例外**额外**需要 `WARP_RUST_TRUSTED_HOST_NET=1`
    /// —— 语义即「部署方已用宿主 `-p 127.0.0.1:...` 限定，对宿主网络栈安全负责」。
    /// 仓库 `scripts/run-docker.sh`、`docker-compose.yml`、`scripts/quickstart.sh`
    /// 都显式注入此 env；走仓库脚本的用户完全无感。手搓 `docker run -p 1080:1080
    /// ghcr.io/...` 且不带 auth 的高危姿势会被堵住（v0.3.2 BREAKING change）。
    pub fn validate(&self) -> Result<(), String> {
        self.validate_with_container(detect_container())
    }

    /// 与 [`Self::validate`] 等价，但容器探测结果作为参数注入，便于单测覆盖两条分支。
    /// 内部读取 `WARP_RUST_TRUSTED_HOST_NET` env 后转交 [`Self::validate_with`]。
    pub fn validate_with_container(&self, is_container: bool) -> Result<(), String> {
        let trusted_host_net =
            std::env::var("WARP_RUST_TRUSTED_HOST_NET").ok().as_deref() == Some("1");
        self.validate_with(is_container, trusted_host_net)
    }

    /// 纯函数版校验：容器探测与「是否信任宿主网络」均由参数注入，**不读任何 env**。
    /// 单测直接调这个版本，避免 process-global env 在并行 cargo test 中互相污染。
    /// （ALLOW_OPEN_PROXY env 仍读，但作为显式 escape hatch，测试默认不触发该路径。）
    pub fn validate_with(&self, is_container: bool, trusted_host_net: bool) -> Result<(), String> {
        let ip = self.server.bind.ip();
        if !ip.is_loopback() && self.server.auth.is_none() {
            // 1) 用户显式声明接受风险，最高优先级（保留 v0.1.1 起的公共契约）
            if std::env::var("WARP_RUST_ALLOW_OPEN_PROXY").ok().as_deref() == Some("1") {
                tracing::warn!(
                    bind = %self.server.bind,
                    "WARP_RUST_ALLOW_OPEN_PROXY=1：跳过开放代理校验（你已显式接受高风险）"
                );
                counter!(M_OPEN_PROXY_ALLOWED).increment(1);
            // 2) 容器内 + 0.0.0.0 + 显式声明信任宿主网络 → 放行（warn + counter）。
            //    代码看不到宿主 -p，必须由部署方对宿主 loopback 限定负责。
            //    仅放行 IPv4 0.0.0.0；IPv6 :: 仍按原策略拒绝（双栈公网监听不在此例外里）。
            } else if is_container
                && ip == std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                && trusted_host_net
            {
                tracing::warn!(
                    bind = %self.server.bind,
                    trusted_host_net = true,
                    "容器内监听 0.0.0.0 + 无 [server.auth] + WARP_RUST_TRUSTED_HOST_NET=1：\
                     放行；假设宿主 -p 已限定到 loopback（如 -p 127.0.0.1:1080:1080）。\
                     若实际用 -p 0.0.0.0:1080:1080 或 -p 1080:1080 暴露到公网，等于开放代理"
                );
                counter!(M_CONTAINER_OPEN_PROXY_WARN).increment(1);
                counter!(M_OPEN_PROXY_ALLOWED).increment(1);
            } else {
                // 容器场景下额外提示 trusted-host-net 这条出路；非容器场景不提（无意义）。
                let container_hint = if is_container
                    && ip == std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                {
                    "\n  · 容器场景（v0.3.2+）：若宿主侧已用 `-p 127.0.0.1:<port>:<port>` 限定到 loopback，\
                     可设环境变量 WARP_RUST_TRUSTED_HOST_NET=1 表示你对宿主网络栈负责。\
                     仓库 scripts/run-docker.sh / docker-compose.yml / scripts/quickstart.sh 已默认注入；\
                     裸 `docker run` 或自定义部署需自己加。"
                } else {
                    ""
                };
                return Err(format!(
                    "拒绝启动：server.bind = {} 不是 loopback，但 [server.auth] 为空。\n  \
                     这等于把无鉴权的 SOCKS5 暴露给互联网。\n  \
                     · 改回本机：把 bind 改成 127.0.0.1:<port>\n  \
                     · 启用鉴权：在 config.toml 加 [server.auth] username/password（≥16 位强密码）\n  \
                     · 显式覆盖（不推荐）：设置环境变量 WARP_RUST_ALLOW_OPEN_PROXY=1{}",
                    self.server.bind,
                    container_hint,
                ));
            }
        }
        // metrics 端口同样校验：含运营信息，公网暴露不可（无 metrics 鉴权机制）
        let m = self.metrics.bind.ip();
        if self.metrics.enabled && !m.is_loopback() {
            tracing::warn!(
                bind = %self.metrics.bind,
                "metrics 监听非 loopback；建议改为 127.0.0.1:9090 或通过反代/SSH 转发访问"
            );
        }
        if self.warp.mtu < 576 || self.warp.mtu > 1420 {
            return Err(format!(
                "[warp] mtu = {} 超出建议范围；请使用 576..=1420，WARP 常用 1280 或 1420",
                self.warp.mtu
            ));
        }
        if self.health.targets.is_empty()
            || self.health.min_successes == 0
            || self.health.min_successes > self.health.targets.len()
        {
            return Err(format!(
                "[health] min_successes={} 必须在 1..=targets.len()={} 范围内",
                self.health.min_successes,
                self.health.targets.len()
            ));
        }
        if self.health.interval.is_zero() || self.health.timeout.is_zero() {
            return Err("[health] interval 和 timeout 必须大于 0".into());
        }
        if self.recovery.reconnect_after == 0
            || self.recovery.reconnect_after > self.recovery.rebuild_config_after
            || self.recovery.rebuild_config_after > self.recovery.reregister_after
            || self.recovery.reregister_after > self.recovery.rotate_identity_after
        {
            return Err(
                "[recovery] 阈值必须非零并按 reconnect <= rebuild <= reregister <= rotate 排列"
                    .into(),
            );
        }
        if self.recovery.backoff_min > self.recovery.backoff_max {
            return Err("[recovery] backoff_min 不能大于 backoff_max".into());
        }
        if self.warp.tcp_buffer_size < 65_535 {
            return Err(format!(
                "[warp] tcp_buffer_size = {} 太小；至少 65535，推荐 262144",
                self.warp.tcp_buffer_size
            ));
        }
        if self.warp.tcp_buffer_size > 8 * 1024 * 1024 {
            return Err(format!(
                "[warp] tcp_buffer_size = {} 过大；上限 8388608",
                self.warp.tcp_buffer_size
            ));
        }
        if self.limits.relay_buffer_size < 4096 {
            return Err(format!(
                "[limits] relay_buffer_size = {} 太小；至少 4096，推荐 65536",
                self.limits.relay_buffer_size
            ));
        }
        if self.limits.relay_buffer_size > 1024 * 1024 {
            return Err(format!(
                "[limits] relay_buffer_size = {} 过大；上限 1048576",
                self.limits.relay_buffer_size
            ));
        }
        if !(1..=16_384).contains(&self.limits.max_concurrent_connections) {
            return Err(format!(
                "[limits] max_concurrent_connections = {} 超出 1..=16384",
                self.limits.max_concurrent_connections
            ));
        }
        if self.limits.max_pending_dials == 0
            || self.limits.max_pending_dials > self.limits.max_concurrent_connections
        {
            return Err(format!(
                "[limits] max_pending_dials={} 必须在 1..=max_concurrent_connections={} 范围内",
                self.limits.max_pending_dials, self.limits.max_concurrent_connections
            ));
        }
        if self.limits.connect_timeout.is_zero() {
            return Err("[limits] connect_timeout 必须大于 0".into());
        }
        if self.limits.handshake_timeout.is_zero() || self.limits.idle_timeout.is_zero() {
            return Err("[limits] handshake_timeout 和 idle_timeout 必须大于 0".into());
        }
        if self.limits.happy_eyeballs_delay.is_zero() {
            return Err("[limits] happy_eyeballs_delay 必须大于 0".into());
        }
        if !(1..=32).contains(&self.limits.max_dial_candidates) {
            return Err("[limits] max_dial_candidates 必须在 1..=32".into());
        }
        if !(1..=4).contains(&self.limits.max_parallel_dials) {
            return Err("[limits] max_parallel_dials 必须在 1..=4".into());
        }
        let max_dial_ports = self
            .limits
            .max_pending_dials
            .saturating_mul(self.limits.max_parallel_dials.saturating_sub(1));
        if self
            .limits
            .max_concurrent_connections
            .saturating_add(max_dial_ports)
            > 32_768
        {
            return Err(
                "[limits] max_concurrent_connections + max_pending_dials * (max_parallel_dials - 1) 不能超过 32768（用户态 TCP 临时端口容量）"
                    .into(),
            );
        }
        if self.dns.max_cache_entries == 0 || self.dns.max_cache_entries > 1_000_000 {
            return Err("[dns] max_cache_entries 必须在 1..=1000000".into());
        }
        if self.dns.timeout.is_zero() {
            return Err("[dns] timeout 必须大于 0".into());
        }
        if self.dns.mode == DnsMode::Tunnel && self.dns.servers.is_empty() {
            return Err("[dns] mode=tunnel 时 servers 不能为空".into());
        }
        let established_capacity = self
            .warp
            .tcp_buffer_size
            .saturating_mul(2)
            .saturating_add(self.limits.relay_buffer_size.saturating_mul(2))
            .saturating_mul(self.limits.max_concurrent_connections);
        let extra_dial_capacity = self
            .warp
            .tcp_buffer_size
            .saturating_mul(2)
            .saturating_mul(self.limits.max_parallel_dials.saturating_sub(1))
            .saturating_mul(self.limits.max_pending_dials);
        let capacity = established_capacity.saturating_add(extra_dial_capacity);
        if capacity > 2 * 1024 * 1024 * 1024usize {
            tracing::warn!(
                estimated_capacity_bytes = capacity,
                "配置的理论连接缓冲容量超过 2GiB；请调低 tcp_buffer_size、relay_buffer_size 或并发上限"
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
            if !ip.is_loopback() {
                let strong = auth.password.len() >= 16
                    && auth.password.bytes().any(|c| c.is_ascii_lowercase())
                    && auth.password.bytes().any(|c| c.is_ascii_uppercase())
                    && auth.password.bytes().any(|c| c.is_ascii_digit());
                if !strong {
                    return Err(
                        "公网监听的 [server.auth] password 必须至少 16 位，并包含大小写字母和数字"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// 容器环境探测：用于把 validate 的开放代理拒绝放宽为 warn。
///
/// 命中任一即认为是容器：
/// - 存在 `/.dockerenv`（Docker / 多数 OCI runtime 都会写）
/// - `/proc/1/cgroup` 含 `docker` / `containerd` / `kubepods` / `podman` / `lxc`
///
/// 故意不读 env（PID/HOSTNAME 之类太脆），有 io；测试请走 `validate_with_container`。
fn detect_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }
    if let Ok(cg) = std::fs::read_to_string("/proc/1/cgroup") {
        for marker in ["docker", "containerd", "kubepods", "podman", "lxc"] {
            if cg.contains(marker) {
                return true;
            }
        }
    }
    false
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

    #[test]
    fn validate_public_long_but_low_entropy_password_rejected() {
        let err = cfg_with("0.0.0.0:1080", Some(("u", "aaaaaaaaaaaaaaaaaaaa")))
            .validate()
            .unwrap_err();
        assert!(err.contains("大小写"));
    }

    #[test]
    fn validate_rejects_dial_concurrency_beyond_port_capacity() {
        let mut cfg = Config::default();
        cfg.limits.max_concurrent_connections = 16_384;
        cfg.limits.max_pending_dials = 16_384;
        cfg.limits.max_parallel_dials = 4;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("32768"));
    }

    #[test]
    fn validate_rejects_pending_dials_above_connection_limit() {
        let mut cfg = Config::default();
        cfg.limits.max_concurrent_connections = 64;
        cfg.limits.max_pending_dials = 65;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_pending_dials"));
    }
}

#[cfg(test)]
mod container_tests {
    use super::*;

    fn cfg(bind: &str) -> Config {
        let mut c = Config::default();
        c.server.bind = bind.parse().unwrap();
        c.server.auth = None;
        c
    }

    // 所有测试都走 validate_with(is_container, trusted_host_net) 直接传参，
    // 不动 process-global env —— 这样和 cargo 默认并行 test 完美兼容，
    // 也不需要 Mutex 串行（参见 v0.3.2 regression review 的核心要求）。

    #[test]
    fn validate_container_v4_no_auth_with_trust_ok() {
        // 容器 + 0.0.0.0 + 无 auth + 显式信任宿主网络 → 放行（warn + counter）
        assert!(cfg("0.0.0.0:1080").validate_with(true, true).is_ok());
    }

    #[test]
    fn validate_container_v4_no_auth_without_trust_rejected() {
        // 关键回归（v0.3.2 新增）：容器 + 0.0.0.0 + 无 auth + 未信任 → 拒绝。
        // 这条直接堵住裸 `docker run -p 1080:1080 ghcr.io/...` 把无鉴权 SOCKS5
        // 挂到宿主 INADDR_ANY 的开放代理姿势（用户决策：Dockerfile 不设默认 ENV，
        // 强制部署方显式 opt-in，BREAKING change）。
        let err = cfg("0.0.0.0:1080").validate_with(true, false).unwrap_err();
        assert!(err.contains("拒绝启动"));
        assert!(
            err.contains("WARP_RUST_TRUSTED_HOST_NET"),
            "容器场景的错误消息必须提示 trusted-host-net 这条出路；实际：{err}"
        );
        // 同时保留 ALLOW_OPEN_PROXY 这条已发布契约的提示
        assert!(err.contains("WARP_RUST_ALLOW_OPEN_PROXY"));
    }

    #[test]
    fn validate_non_container_v4_no_auth_still_rejected() {
        // 主机直跑：即便 trusted=true 也必须拒绝 —— trust 只对容器+0.0.0.0 组合生效。
        let err = cfg("0.0.0.0:1080").validate_with(false, true).unwrap_err();
        assert!(err.contains("拒绝启动"));
    }

    #[test]
    fn validate_container_v6_unspecified_still_rejected() {
        // 容器例外仅覆盖 IPv4 0.0.0.0；:: 仍走原策略，即便 trusted=true 也拒
        let err = cfg("[::]:1080").validate_with(true, true).unwrap_err();
        assert!(err.contains("拒绝启动"));
    }
}
