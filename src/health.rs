//! 周期性健康探针 —— 并发拨号配置的多个 Cloudflare/外部目标，以多数派判断
//! WireGuard、netstack 与真实公网出口是否健康。结果发给 supervisor 恢复状态机。

use crate::config::HealthConfig;
use crate::error::Error;
use crate::metrics::{M_PROBE_FAIL, M_PROBE_OK};
use crate::supervisor::SupervisorEvent;
use crate::tunnel::Tunnel;
use metrics::counter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

pub async fn probe_loop(
    tunnel: Arc<Tunnel>,
    cfg: HealthConfig,
    tx: mpsc::Sender<SupervisorEvent>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // interval 的首次 tick 立即执行：启动时只验证了 WireGuard 握手，尚未验证
    // 公网出口；不能在第一个 30s 窗口里把半健康隧道暴露为 ready。

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!("health probe stopping");
                return;
            }
            _ = ticker.tick() => {
                let observed_at = std::time::Instant::now();
                let evt = match probe_targets(
                    tunnel.clone(),
                    &cfg.targets,
                    cfg.min_successes,
                    cfg.timeout,
                ).await {
                    Ok(()) => {
                        trace!("probe ok");
                        counter!(M_PROBE_OK).increment(1);
                        SupervisorEvent::ProbeOk { observed_at }
                    }
                    Err(e) => {
                        debug!(error = %e, "probe failed");
                        counter!(M_PROBE_FAIL).increment(1);
                        SupervisorEvent::ProbeFailed { reason: e.to_string(), observed_at }
                    }
                };
                let _ = tx.send(evt).await;
            }
        }
    }
}

async fn probe_targets(
    tunnel: Arc<Tunnel>,
    targets: &[SocketAddr],
    min_successes: usize,
    timeout: Duration,
) -> Result<(), Error> {
    let mut probes = tokio::task::JoinSet::new();
    for &target in targets {
        let tunnel = tunnel.clone();
        probes.spawn(async move { (target, probe_once(&tunnel, target, timeout).await) });
    }

    let mut successes = 0usize;
    let mut failures = Vec::new();
    while let Some(result) = probes.join_next().await {
        match result {
            Ok((_target, Ok(()))) => successes += 1,
            Ok((target, Err(e))) => failures.push(format!("{target}: {e}")),
            Err(e) => failures.push(format!("probe task: {e}")),
        }
        if successes >= min_successes {
            probes.shutdown().await;
            return Ok(());
        }
        if successes + probes.len() < min_successes {
            probes.shutdown().await;
            break;
        }
    }

    Err(Error::other(format!(
        "egress quorum failed ({successes}/{min_successes} required): {}",
        failures.join("; ")
    )))
}

async fn probe_once(tunnel: &Tunnel, target: SocketAddr, timeout: Duration) -> Result<(), Error> {
    match tokio::time::timeout(timeout, tunnel.dial_tcp(target)).await {
        Ok(Ok(_conn)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::other(format!("probe timeout after {:?}", timeout))),
    }
}
