//! 周期性健康探针 —— 并发拨号配置的多个 Cloudflare/外部目标，以多数派判断
//! WireGuard、netstack 与真实公网出口是否健康。结果发给 supervisor 恢复状态机。

use crate::config::HealthConfig;
use crate::error::Error;
use crate::metrics::{M_PROBE_FAIL, M_PROBE_OK, M_PROBE_TARGET_FAIL};
use crate::supervisor::SupervisorEvent;
use crate::tunnel::Tunnel;
use metrics::counter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

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

    // 等所有目标完成（并发，最坏 = 单个 timeout ≈ 8s）。**不再**一到 quorum 就
    // 取消其余目标——那会永久隐藏「Google 全挂但 1.1.1.1/9.9.9.9 正常」这类选择性
    // 故障，正是之前「探针 ok 却全站 timeout」矛盾的来源。达标与否仍按 min_successes 判。
    let mut successes = 0usize;
    let mut failures = Vec::new();
    while let Some(result) = probes.join_next().await {
        match result {
            Ok((_target, Ok(()))) => successes += 1,
            Ok((target, Err(e))) => {
                counter!(M_PROBE_TARGET_FAIL, "target" => target.to_string()).increment(1);
                failures.push(format!("{target}: {e}"));
            }
            Err(e) => failures.push(format!("probe task: {e}")),
        }
    }

    if successes >= min_successes {
        // 达标即健康，但有目标失败要留痕（日志 + 已在上面按 target 计数），
        // 让选择性/部分出口故障可见，而不是被 quorum 掩盖。
        if !failures.is_empty() {
            warn!(
                successes,
                min_successes,
                failed = %failures.join("; "),
                "health probe passed quorum but some targets failed (possible selective/partial egress issue)"
            );
        }
        Ok(())
    } else {
        Err(Error::other(format!(
            "egress quorum failed ({successes}/{min_successes} required): {}",
            failures.join("; ")
        )))
    }
}

async fn probe_once(tunnel: &Tunnel, target: SocketAddr, timeout: Duration) -> Result<(), Error> {
    match tokio::time::timeout(timeout, tunnel.dial_tcp(target)).await {
        Ok(Ok(_conn)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::other(format!("probe timeout after {:?}", timeout))),
    }
}
