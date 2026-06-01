//! WARP 账号管理：首次启动时向 Cloudflare 注册，持久化凭据，按需刷新
//! WireGuard 配置。
//!
//! **整个项目只有这一个模块会调用 Cloudflare API**。注册冷却保护也放在这
//! 里，避免某次失败后被 supervisor 一遍遍地反复触发重注册。

use crate::config::WarpConfig;
use crate::error::{Error, Result};
use crate::warp::persistence;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use warp_wireguard_gen::{
    get_config, register, update_license, RegistrationOptions, WarpCredentials,
};
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

pub struct AccountManager {
    cfg: WarpConfig,
    /// 锁定一切会改 `account.json` 或调 WARP API 的操作，确保注册冷却被严格遵守
    api_lock: Mutex<()>,
}

impl AccountManager {
    pub fn new(cfg: WarpConfig) -> Self {
        Self {
            cfg,
            api_lock: Mutex::new(()),
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
        self.register_inner().await
    }

    /// 强制重新注册（会先校验注册冷却）。调用方需保证此前已经决定要丢弃旧 account.json。
    pub async fn reregister(&self) -> Result<AccountSnapshot> {
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

        self.register_inner().await
    }

    /// 单独刷新 WG 配置（被 supervisor 的周期定时器调用）。
    pub async fn refresh_config(&self, creds: &WarpCredentials) -> Result<WireGuardConfig> {
        let _guard = self.api_lock.lock().await;
        debug!("refreshing WARP WG config");
        let mut wg_config = get_config(creds).await?;
        self.apply_transport_tuning(&mut wg_config);
        Ok(wg_config)
    }

    async fn register_inner(&self) -> Result<AccountSnapshot> {
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

        // 配了 license_key 时再单独绑一次（某些端点把 license 绑定放在注册之外的独立调用里）
        if let Some(key) = &self.cfg.license_key {
            if let Err(e) = update_license(&credentials, key).await {
                warn!(error = %e, "update_license failed (continuing anyway)");
            }
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        persistence::save(
            &self.account_path(),
            &AccountFile {
                credentials: credentials.clone(),
                registered_at: now,
            },
        )?;

        Ok(AccountSnapshot {
            wg_config,
            credentials,
        })
    }
}
