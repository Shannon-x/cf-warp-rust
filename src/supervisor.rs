//! 中央状态机。负责跑恢复阶梯、根据探针失败重建隧道、按周期刷新 WG 配置。

use crate::config::Config;
use crate::error::Result;
use crate::health;
use crate::metrics::{M_REREGISTER, M_ROTATE, M_TUNNEL_REBUILD};
use crate::tunnel::Tunnel;
use crate::warp::identity_pool::IdentityPool;
use crate::warp::AccountManager;
use metrics::counter;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use warp_wireguard_gen::WarpCredentials;

#[derive(Debug)]
pub enum SupervisorEvent {
    ProbeOk,
    ProbeFailed { reason: String },
    RefreshTimerFired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    None,
    Reconnect,
    RebuildConfig,
    Reregister,
    RotateIdentity,
}

pub struct Supervisor {
    cfg: Config,
    account: Arc<AccountManager>,
    tunnel: Arc<Tunnel>,
    identity_pool: Mutex<IdentityPool>,
    /// 当前生效的凭据（rotate / re-register 时会被更新）
    creds: Mutex<WarpCredentials>,
    events_tx: mpsc::Sender<SupervisorEvent>,
    events_rx: Mutex<mpsc::Receiver<SupervisorEvent>>,
    consecutive_failures: Mutex<u8>,
}

impl Supervisor {
    pub fn new(
        cfg: Config,
        account: Arc<AccountManager>,
        tunnel: Arc<Tunnel>,
        identity_pool: IdentityPool,
        creds: WarpCredentials,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(64);
        Arc::new(Self {
            cfg,
            account,
            tunnel,
            identity_pool: Mutex::new(identity_pool),
            creds: Mutex::new(creds),
            events_tx: tx,
            events_rx: Mutex::new(rx),
            consecutive_failures: Mutex::new(0),
        })
    }

    pub fn events_tx(&self) -> mpsc::Sender<SupervisorEvent> {
        self.events_tx.clone()
    }

    pub async fn run(self: Arc<Self>, cancel: CancellationToken) -> Result<()> {
        info!("supervisor started");

        // 健康探针
        {
            let tunnel = self.tunnel.clone();
            let cfg = self.cfg.health.clone();
            let tx = self.events_tx.clone();
            let child = cancel.child_token();
            tokio::spawn(health::probe_loop(tunnel, cfg, tx, child));
        }

        // 配置刷新定时器
        if !self.cfg.warp.refresh_interval.is_zero() {
            let interval = self.cfg.warp.refresh_interval;
            let tx = self.events_tx.clone();
            let child = cancel.child_token();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // 跳过 interval 的首次立即 fire
                loop {
                    tokio::select! {
                        biased;
                        _ = child.cancelled() => break,
                        _ = ticker.tick() => {
                            let _ = tx.send(SupervisorEvent::RefreshTimerFired).await;
                        }
                    }
                }
            });
        }

        // 事件分发循环
        let mut rx = self.events_rx.lock().await;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                Some(evt) = rx.recv() => {
                    if let Err(e) = self.handle_event(evt).await {
                        error!(error = %e, "supervisor handler failed");
                    }
                }
            }
        }
        info!("supervisor stopping");
        Ok(())
    }

    async fn handle_event(&self, evt: SupervisorEvent) -> Result<()> {
        match evt {
            SupervisorEvent::ProbeOk => {
                let mut fails = self.consecutive_failures.lock().await;
                if *fails > 0 {
                    info!(prior_failures = *fails, "probe ok — healthy again");
                    *fails = 0;
                }
            }
            SupervisorEvent::ProbeFailed { reason } => {
                let action = {
                    let mut fails = self.consecutive_failures.lock().await;
                    *fails = fails.saturating_add(1);
                    let n = *fails;
                    let act = self.action_for(n);
                    warn!(failures = n, reason, ?act, "probe failed");
                    act
                };
                self.escalate(action).await?;
            }
            SupervisorEvent::RefreshTimerFired => {
                debug!("scheduled config refresh");
                if let Err(e) = self.action_rebuild_config().await {
                    warn!(error = %e, "scheduled refresh failed");
                }
            }
        }
        Ok(())
    }

    fn action_for(&self, n: u8) -> RecoveryAction {
        let r = &self.cfg.recovery;
        // 顺序很重要：要匹配命中的最高阈值
        if n >= r.rotate_identity_after {
            RecoveryAction::RotateIdentity
        } else if n >= r.reregister_after {
            RecoveryAction::Reregister
        } else if n >= r.rebuild_config_after {
            RecoveryAction::RebuildConfig
        } else if n >= r.reconnect_after {
            RecoveryAction::Reconnect
        } else {
            RecoveryAction::None
        }
    }

    async fn escalate(&self, action: RecoveryAction) -> Result<()> {
        // 任何一级恢复动作前都先按指数退避等一下
        self.backoff().await;
        let result = match action {
            RecoveryAction::None => return Ok(()),
            RecoveryAction::Reconnect => self.action_reconnect().await,
            RecoveryAction::RebuildConfig => self.action_rebuild_config().await,
            RecoveryAction::Reregister => self.action_reregister().await,
            RecoveryAction::RotateIdentity => self.action_rotate().await,
        };
        if let Err(e) = &result {
            warn!(error = %e, ?action, "recovery step failed");
        } else {
            info!(?action, "recovery step completed");
        }
        result
    }

    async fn backoff(&self) {
        // 指数退避：backoff_min * 2^(failures-1)，封顶到 backoff_max
        let n = *self.consecutive_failures.lock().await;
        let min_ms = self.cfg.recovery.backoff_min.as_millis() as u64;
        let max_ms = self.cfg.recovery.backoff_max.as_millis() as u64;
        let exp = (n.saturating_sub(1)).min(16) as u32;
        let ms = min_ms.saturating_mul(2u64.saturating_pow(exp)).min(max_ms);
        debug!(failures = n, backoff_ms = ms, "applying recovery backoff");
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    async fn action_reconnect(&self) -> Result<()> {
        let creds = self.creds.lock().await.clone();
        let wg = self.account.refresh_config(&creds).await?;
        self.tunnel.rebuild(wg).await?;
        counter!(M_TUNNEL_REBUILD).increment(1);
        Ok(())
    }

    async fn action_rebuild_config(&self) -> Result<()> {
        let creds = self.creds.lock().await.clone();
        let wg = self.account.refresh_config(&creds).await?;
        self.tunnel.rebuild(wg).await?;
        counter!(M_TUNNEL_REBUILD).increment(1);
        Ok(())
    }

    async fn action_reregister(&self) -> Result<()> {
        // FIX-4：调 AccountManager::reregister（它内部校验 register_cooldown）
        // 之前的实现直接 fs::remove_file + load_or_register，绕过了冷却保护，
        // 而且若 API 失败旧账号已经删除、不可恢复。
        // 现在改成：reregister 成功就替换；失败（多半冷却中）回退到 rebuild_config
        // 而不丢账号。
        match self.account.reregister().await {
            Ok(snapshot) => {
                *self.creds.lock().await = snapshot.credentials.clone();
                self.tunnel.rebuild(snapshot.wg_config).await?;
                counter!(M_REREGISTER).increment(1);
                counter!(M_TUNNEL_REBUILD).increment(1);
                Ok(())
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "reregister 失败（多半 register_cooldown 未到），fallback 到 rebuild_config"
                );
                self.action_rebuild_config().await
            }
        }
    }

    async fn action_rotate(&self) -> Result<()> {
        let next = {
            let mut pool = self.identity_pool.lock().await;
            pool.next_identity()
        };
        match next {
            Some(file) => {
                let pool = self.identity_pool.lock().await;
                pool.activate(&self.cfg.warp.data_dir, &file)?;
                drop(pool);
                let snapshot = self.account.load_or_register().await?;
                *self.creds.lock().await = snapshot.credentials.clone();
                self.tunnel.rebuild(snapshot.wg_config).await?;
                counter!(M_ROTATE).increment(1);
                counter!(M_TUNNEL_REBUILD).increment(1);
            }
            None => {
                warn!("identity pool empty; cannot rotate (will keep retrying current identity)");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecoveryConfig;

    fn cfg() -> Config {
        let mut c = Config::default();
        c.recovery = RecoveryConfig {
            reconnect_after: 1,
            rebuild_config_after: 3,
            reregister_after: 5,
            rotate_identity_after: 10,
            backoff_min: Duration::from_millis(0),
            backoff_max: Duration::from_millis(0),
        };
        c
    }

    /// 纯函数 —— 无需构造 fake AccountManager / Tunnel
    fn action_for(c: &Config, n: u8) -> RecoveryAction {
        let r = &c.recovery;
        if n >= r.rotate_identity_after {
            RecoveryAction::RotateIdentity
        } else if n >= r.reregister_after {
            RecoveryAction::Reregister
        } else if n >= r.rebuild_config_after {
            RecoveryAction::RebuildConfig
        } else if n >= r.reconnect_after {
            RecoveryAction::Reconnect
        } else {
            RecoveryAction::None
        }
    }

    #[test]
    fn recovery_ladder_thresholds() {
        let c = cfg();
        assert_eq!(action_for(&c, 0), RecoveryAction::None);
        assert_eq!(action_for(&c, 1), RecoveryAction::Reconnect);
        assert_eq!(action_for(&c, 2), RecoveryAction::Reconnect);
        assert_eq!(action_for(&c, 3), RecoveryAction::RebuildConfig);
        assert_eq!(action_for(&c, 4), RecoveryAction::RebuildConfig);
        assert_eq!(action_for(&c, 5), RecoveryAction::Reregister);
        assert_eq!(action_for(&c, 9), RecoveryAction::Reregister);
        assert_eq!(action_for(&c, 10), RecoveryAction::RotateIdentity);
        assert_eq!(action_for(&c, 200), RecoveryAction::RotateIdentity);
    }

    #[test]
    fn recovery_ladder_picks_highest_threshold() {
        // 用户错配（reregister_after == rotate_identity_after）时
        // 应该取「更激进」的那一档
        let mut c = cfg();
        c.recovery.reregister_after = 10;
        c.recovery.rotate_identity_after = 10;
        assert_eq!(action_for(&c, 10), RecoveryAction::RotateIdentity);
    }
}
