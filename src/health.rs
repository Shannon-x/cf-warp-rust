//! 周期性健康探针 —— 并发拨号配置的多个 Cloudflare/外部目标，以多数派判断
//! WireGuard、netstack 与真实公网出口是否健康。结果发给 supervisor 恢复状态机。
//!
//! v0.4.6 起，一轮健康判定由**三个**独立信号合成，而不再只看拨号探针：
//!
//! 1. **WireGuard 会话是否新鲜**（`time_since_last_handshake`）。活跃会话每
//!    ~120s 重握手，显著超时就说明会话已死，此时无需再等一个完整的探针超时。
//!    这个能力 vendored crate 一直提供，但在此之前 `src/` 里零调用。
//! 2. **拨号探针**（原有逻辑）。
//! 3. **业务出口成功率**（`EgressStats`）。这是补上「探针全绿但业务全挂」这个
//!    结构性盲区的唯一办法：`health.targets` 是 `Vec<SocketAddr>`，只能填 IP，
//!    覆盖不了「域名解析 → 第三方 Web 前端」这条真实路径；而默认三个目标全是
//!    DNS/CDN anycast，`min_successes = 2` 又允许其中一个挂掉。现场因此出现过
//!    业务成功率 ~1% 而探针一路全绿、隧道数小时不被重建。

use crate::config::HealthConfig;
use crate::egress::EgressStats;
use crate::error::Error;
use crate::metrics::{
    M_EGRESS_DEGRADED, M_HANDSHAKE_STALE, M_PROBE_FAIL, M_PROBE_OK, M_PROBE_TARGET_FAIL,
};
use crate::supervisor::SupervisorEvent;
use crate::tunnel::Tunnel;
use metrics::counter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

/// WireGuard 会话超过这么久没有成功握手就视为陈旧。
///
/// 活跃会话的重握手周期约 120s，180s 给了 1.5 倍余量，既不会误杀正常的
/// keepalive 抖动，又能在拨号大面积超时之前就把问题暴露出来。
const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(180);

/// 业务出口连续这么多轮判定为降级，才据此推动恢复阶梯。
///
/// 要求连续两轮（默认 60s）是为了避免单轮抖动就触发整条重建/重注册阶梯——
/// 重建会切断当时所有在途连接，误触发的代价不低。
const EGRESS_DEGRADED_ROUNDS: u32 = 2;

pub async fn probe_loop(
    tunnel: Arc<Tunnel>,
    cfg: HealthConfig,
    egress: Arc<EgressStats>,
    tx: mpsc::Sender<SupervisorEvent>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut degraded_rounds: u32 = 0;
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

                // 信号 1：WireGuard 会话是否还新鲜。比拨号快得多，先判。
                let stale_handshake = tunnel
                    .time_since_last_handshake()
                    .filter(|since| *since > HANDSHAKE_STALE_AFTER);

                // 信号 2：拨号探针。
                let probe = probe_targets(
                    tunnel.clone(),
                    &cfg.targets,
                    cfg.min_successes,
                    cfg.timeout,
                ).await;

                // 信号 3：业务出口成功率。窗口必须**每轮都取走**，否则旧数据
                // 会一直累积并污染后续判断。
                let window = egress.take_window();
                if window.is_degraded() {
                    degraded_rounds = degraded_rounds.saturating_add(1);
                } else {
                    degraded_rounds = 0;
                }
                let egress_degraded = degraded_rounds >= EGRESS_DEGRADED_ROUNDS;

                let evt = if let Some(since) = stale_handshake {
                    counter!(M_HANDSHAKE_STALE).increment(1);
                    counter!(M_PROBE_FAIL).increment(1);
                    warn!(?since, "WireGuard 会话陈旧，判定隧道不健康");
                    SupervisorEvent::ProbeFailed {
                        reason: format!("WireGuard handshake stale for {since:?}"),
                        observed_at,
                    }
                } else if let Err(e) = probe {
                    debug!(error = %e, "probe failed");
                    counter!(M_PROBE_FAIL).increment(1);
                    SupervisorEvent::ProbeFailed { reason: e.to_string(), observed_at }
                } else if egress_degraded {
                    // 探针过了但业务在挂 —— 正是「选择性出口故障」的形态：
                    // 探针目标（DNS/CDN anycast）可达，业务目标（域名 → 第三方
                    // Web 前端）全挂。此前这种情况隧道永远不会被重建。
                    counter!(M_EGRESS_DEGRADED).increment(1);
                    counter!(M_PROBE_FAIL).increment(1);
                    degraded_rounds = 0;
                    warn!(
                        ok = window.ok,
                        failed = window.failed,
                        fail_ratio = window.fail_ratio(),
                        rounds = EGRESS_DEGRADED_ROUNDS,
                        "拨号探针通过但业务出口成功率过低，判定为选择性出口故障"
                    );
                    SupervisorEvent::ProbeFailed {
                        reason: format!(
                            "egress degraded: {}/{} business dials failed ({:.0}%) while probes passed",
                            window.failed,
                            window.total(),
                            window.fail_ratio() * 100.0
                        ),
                        observed_at,
                    }
                } else {
                    trace!("probe ok");
                    counter!(M_PROBE_OK).increment(1);
                    SupervisorEvent::ProbeOk { observed_at }
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
