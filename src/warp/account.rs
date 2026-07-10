//! WARP 账号管理：首次启动时向 Cloudflare 注册，持久化凭据，按需刷新
//! WireGuard 配置。
//!
//! **整个项目只有这一个模块会调用 Cloudflare API**。注册冷却保护也放在这
//! 里，避免某次失败后被 supervisor 一遍遍地反复触发重注册。

use crate::config::WarpConfig;
use crate::error::{Error, Result};
use crate::warp::persistence;
use parking_lot::Mutex as ParkingMutex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use warp_wireguard_gen::{get_config, register, RegistrationOptions, WarpCredentials};
use wireguard_netstack::WireGuardConfig;

/// 持久化文件的形状
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountFile {
    pub credentials: WarpCredentials,
    /// UNIX 时间戳（秒），记录上一次成功（重）注册的时间
    #[serde(default)]
    pub registered_at: u64,
}

/// 一次成功启动后程序需要的全部信息：可直接 connect 的 WG 配置 + 后续用于刷新的凭据。
#[derive(Clone)]
pub struct AccountSnapshot {
    pub wg_config: WireGuardConfig,
    pub credentials: WarpCredentials,
}

/// 尚未激活的账号候选。只有候选隧道完成 WireGuard 握手后，
/// supervisor 才会持久化 `account_file` 并原子切换隧道。
pub struct AccountCandidate {
    pub wg_config: WireGuardConfig,
    pub account_file: AccountFile,
}

pub struct AccountManager {
    cfg: WarpConfig,
    /// 锁定一切会改 `account.json` 或调 WARP API 的操作，确保注册冷却被严格遵守
    api_lock: Mutex<()>,
    /// 内存中的最近重注册尝试。候选隧道握手失败时不会覆盖旧
    /// account.json，因此单靠持久化时间戳会连续注册多个新账号。
    last_register_attempt: ParkingMutex<Option<Instant>>,
}

impl AccountManager {
    pub fn new(cfg: WarpConfig) -> Self {
        Self {
            cfg,
            api_lock: Mutex::new(()),
            last_register_attempt: ParkingMutex::new(None),
        }
    }

    fn account_path(&self) -> PathBuf {
        self.cfg.data_dir.join("account.json")
    }

    fn apply_transport_tuning(&self, wg_config: &mut WireGuardConfig) {
        wg_config.mtu = Some(self.cfg.mtu);
        wg_config.tcp_buffer_size = Some(self.cfg.tcp_buffer_size);
    }

    /// 已有持久化凭据时加载并向 Cloudflare 拉一份最新 WG 配置；否则发起一次全新注册。
    pub async fn load_or_register(&self) -> Result<AccountSnapshot> {
        let _guard = self.api_lock.lock().await;
        let path = self.account_path();

        if let Some(file) = persistence::load::<AccountFile>(&path)? {
            info!(
                device_id = %file.credentials.device_id,
                "loaded credentials from {}",
                path.display()
            );
            // 刷一次配置：成本很低，但能让长时间离线后的恢复更快
            let mut wg_config = get_config(&file.credentials).await?;
            self.apply_transport_tuning(&mut wg_config);
            return Ok(AccountSnapshot {
                wg_config,
                credentials: file.credentials,
            });
        }

        info!("no account.json found; registering with Cloudflare WARP");
        let candidate = self.register_candidate().await?;
        persistence::save(&path, &candidate.account_file)?;
        Ok(AccountSnapshot {
            wg_config: candidate.wg_config,
            credentials: candidate.account_file.credentials,
        })
    }

    /// 准备一个重注册候选（先校验注册冷却），但不覆盖现用账号。
    pub async fn prepare_reregister(&self) -> Result<AccountCandidate> {
        let _guard = self.api_lock.lock().await;
        let path = self.account_path();

        if let Some(file) = persistence::load::<AccountFile>(&path)? {
            let last = SystemTime::UNIX_EPOCH + Duration::from_secs(file.registered_at);
            if let Ok(elapsed) = SystemTime::now().duration_since(last) {
                if elapsed < self.cfg.register_cooldown {
                    let remaining = self.cfg.register_cooldown - elapsed;
                    warn!(
                        cooldown_remaining_secs = remaining.as_secs(),
                        "re-register requested but cooldown not elapsed; skipping"
                    );
                    return Err(Error::other(format!(
                        "register cooldown active, {}s remaining",
                        remaining.as_secs()
                    )));
                }
            }
        }

        {
            let mut last_attempt = self.last_register_attempt.lock();
            if let Some(elapsed) = last_attempt.map(|last| last.elapsed()) {
                if elapsed < self.cfg.register_cooldown {
                    let remaining = self.cfg.register_cooldown - elapsed;
                    return Err(Error::other(format!(
                        "register cooldown active after recent attempt, {}s remaining",
                        remaining.as_secs()
                    )));
                }
            }
            // 在网络调用之前记录：API 失败也必须受冷却限制。
            *last_attempt = Some(Instant::now());
        }

        self.register_candidate().await
    }

    /// 单独刷新 WG 配置（被 supervisor 的周期定时器调用）。
    pub async fn refresh_config(&self, creds: &WarpCredentials) -> Result<WireGuardConfig> {
        let _guard = self.api_lock.lock().await;
        debug!("refreshing WARP WG config");
        let mut wg_config = get_config(creds).await?;
        self.apply_transport_tuning(&mut wg_config);
        Ok(wg_config)
    }

    /// 验证候选身份并拉取 WG 配置，但不覆盖当前 `account.json`。
    pub async fn prepare_identity(&self, source: &Path) -> Result<AccountCandidate> {
        let _guard = self.api_lock.lock().await;
        let file = persistence::load::<AccountFile>(source)?.ok_or_else(|| {
            Error::other(format!("identity file disappeared: {}", source.display()))
        })?;
        let mut wg_config = get_config(&file.credentials).await?;
        self.apply_transport_tuning(&mut wg_config);
        Ok(AccountCandidate {
            wg_config,
            account_file: file,
        })
    }

    /// 候选隧道已经完成握手后，才调用此方法原子提交账号。
    pub async fn commit_candidate(&self, file: &AccountFile) -> Result<()> {
        let _guard = self.api_lock.lock().await;
        persistence::save(&self.account_path(), file)
    }

    async fn register_candidate(&self) -> Result<AccountCandidate> {
        let options = RegistrationOptions {
            device_model: self.cfg.device_model.clone(),
            license_key: self.cfg.license_key.clone(),
            teams: None,
        };

        let (mut wg_config, credentials) = register(options).await?;
        // 注入用户配置的传输参数（覆盖 warp-wireguard-gen 返回的默认值）
        self.apply_transport_tuning(&mut wg_config);
        info!(
            device_id = %credentials.device_id,
            mtu = self.cfg.mtu,
            tcp_buffer_size = self.cfg.tcp_buffer_size,
            "WARP registration ok"
        );

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(AccountCandidate {
            wg_config,
            account_file: AccountFile {
                credentials: credentials.clone(),
                registered_at: now,
            },
        })
    }
}
