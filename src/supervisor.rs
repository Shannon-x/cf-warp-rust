//! 中央状态机。负责跑恢复阶梯、根据探针失败重建隧道、按周期刷新 WG 配置。

use crate::config::Config;
use crate::error::Result;
use crate::health;
use crate::metrics::{M_REREGISTER, M_ROTATE, M_TUNNEL_REBUILD};
use crate::tunnel::Tunnel;
use crate::warp::identity_pool::IdentityPool;
use crate::warp::AccountManager;
use metrics::counter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use warp_wireguard_gen::WarpCredentials;
use wireguard_netstack::WireGuardConfig;

#[derive(Debug)]
pub enum SupervisorEvent {
    ProbeOk {
        observed_at: Instant,
    },
    ProbeFailed {
        reason: String,
        observed_at: Instant,
    },
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
    /// 当前已验证的隧道配置。第一级 Reconnect 直接复用，不访问 API。
    wg_config: Mutex<WireGuardConfig>,
    events_tx: mpsc::Sender<SupervisorEvent>,
    events_rx: Mutex<mpsc::Receiver<SupervisorEvent>>,
    consecutive_failures: Mutex<u8>,
    /// 恢复完成前观测到、但排队到恢复完成后才处理的探针必须丢弃；否则旧失败
    /// 会立即推动恢复阶梯，造成无谓的重注册/身份轮换风暴。
    last_recovery_completed: Mutex<Option<Instant>>,
    healthy: Arc<AtomicBool>,
}

impl Supervisor {
    pub fn new(
        cfg: Config,
        account: Arc<AccountManager>,
        tunnel: Arc<Tunnel>,
        identity_pool: IdentityPool,
        creds: WarpCredentials,
        wg_config: WireGuardConfig,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(64);
        Arc::new(Self {
            cfg,
            account,
            tunnel,
            identity_pool: Mutex::new(identity_pool),
            creds: Mutex::new(creds),
            wg_config: Mutex::new(wg_config),
            events_tx: tx,
            events_rx: Mutex::new(rx),
            consecutive_failures: Mutex::new(0),
            last_recovery_completed: Mutex::new(None),
            healthy: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn health_flag(&self) -> Arc<AtomicBool> {
        self.healthy.clone()
    }

    pub async fn run(self: Arc<Self>, cancel: CancellationToken) -> Result<()> {
        info!("supervisor started");
        let mut background = tokio::task::JoinSet::new();

        // 健康探针
        {
            let tunnel = self.tunnel.clone();
            let cfg = self.cfg.health.clone();
            let tx = self.events_tx.clone();
            let child = cancel.child_token();
            background.spawn(health::probe_loop(tunnel, cfg, tx, child));
        }

        // 配置刷新定时器
        if !self.cfg.warp.refresh_interval.is_zero() {
            let interval = self.cfg.warp.refresh_interval;
            let tx = self.events_tx.clone();
            let child = cancel.child_token();
            background.spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                ticker.tick().await; // 跳过 interval 的首次立即 fire
                loop {
                    tokio::select! {
                        biased;
                        _ = child.cancelled() => break,
                        _ = ticker.tick() => {
                            if tx.send(SupervisorEvent::RefreshTimerFired).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        } else {
            info!("scheduled WARP config refresh disabled");
        }

        // 事件分发循环
        let mut rx = self.events_rx.lock().await;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    background.shutdown().await;
                    break;
                },
                joined = background.join_next(), if !background.is_empty() => {
                    return Err(match joined {
                        Some(Ok(())) => crate::error::Error::other("supervisor background task exited unexpectedly"),
                        Some(Err(e)) => crate::error::Error::other(format!("supervisor background task failed: {e}")),
                        None => crate::error::Error::other("supervisor background tasks disappeared"),
                    });
                }
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
            SupervisorEvent::ProbeOk { observed_at } => {
                if self.probe_is_stale(observed_at).await {
                    debug!("discarding stale successful probe");
                    return Ok(());
                }
                self.healthy.store(true, Ordering::Release);
                let mut fails = self.consecutive_failures.lock().await;
                if *fails > 0 {
                    info!(prior_failures = *fails, "probe ok — healthy again");
                    *fails = 0;
                }
            }
            SupervisorEvent::ProbeFailed {
                reason,
                observed_at,
            } => {
                if self.probe_is_stale(observed_at).await {
                    debug!(reason, "discarding stale failed probe");
                    return Ok(());
                }
                self.healthy.store(false, Ordering::Release);
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

    async fn probe_is_stale(&self, observed_at: Instant) -> bool {
        self.last_recovery_completed
            .lock()
            .await
            .is_some_and(|completed| observed_at <= completed)
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
            *self.last_recovery_completed.lock().await = Some(Instant::now());
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
        let wg = self.wg_config.lock().await.clone();
        let active_wg = self.tunnel.rebuild(wg).await?;
        *self.wg_config.lock().await = active_wg;
        counter!(M_TUNNEL_REBUILD).increment(1);
        Ok(())
    }

    async fn action_rebuild_config(&self) -> Result<()> {
        let creds = self.creds.lock().await.clone();
        let wg = self.account.refresh_config(&creds).await?;
        let active_wg = self.tunnel.rebuild(wg).await?;
        *self.wg_config.lock().await = active_wg;
        counter!(M_TUNNEL_REBUILD).increment(1);
        Ok(())
    }

    async fn action_reregister(&self) -> Result<()> {
        // 候选账号和候选隧道都成功后才提交，任何 API/握手/磁盘错误
        // 都会保留当前可用账号与隧道。
        match self.account.prepare_reregister().await {
            Ok(candidate) => {
                let next_wg = candidate.wg_config;
                let connected = Tunnel::connect_candidate(next_wg).await?;
                self.account
                    .commit_candidate(&candidate.account_file)
                    .await?;
                *self.creds.lock().await = candidate.account_file.credentials.clone();
                *self.wg_config.lock().await = connected.config;
                self.tunnel.replace(connected.managed);
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
                let candidate = self.account.prepare_identity(&file).await?;
                let next_wg = candidate.wg_config;
                let connected = Tunnel::connect_candidate(next_wg).await?;
                self.account
                    .commit_candidate(&candidate.account_file)
                    .await?;
                *self.creds.lock().await = candidate.account_file.credentials.clone();
                *self.wg_config.lock().await = connected.config;
                self.tunnel.replace(connected.managed);
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
        Config {
            recovery: RecoveryConfig {
                reconnect_after: 1,
                rebuild_config_after: 3,
                reregister_after: 5,
                rotate_identity_after: 10,
                backoff_min: Duration::from_millis(0),
                backoff_max: Duration::from_millis(0),
            },
            ..Config::default()
        }
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
