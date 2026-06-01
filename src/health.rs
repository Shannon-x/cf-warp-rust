//! 周期性健康探针 —— 通过隧道拨号 1.1.1.1:443。成功即证明 WireGuard 握手
//! 还有效、netstack 与 Cloudflare 之间的 TCP 链路通畅。失败结果会以事件
//! 形式发到 supervisor，由 supervisor 决定如何处理。

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

const PROBE_TARGET: &str = "1.1.1.1:443";

pub async fn probe_loop(
    tunnel: Arc<Tunnel>,
    cfg: HealthConfig,
    tx: mpsc::Sender<SupervisorEvent>,
    cancel: CancellationToken,
) {
    let target: SocketAddr = PROBE_TARGET.parse().expect("static probe target");
    let mut ticker = tokio::time::interval(cfg.interval);
    // 跳过 interval 的首个立即 tick —— 启动流程已经验证过链路一次了
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!("health probe stopping");
                return;
            }
            _ = ticker.tick() => {
                let evt = match probe_once(&tunnel, target, cfg.timeout).await {
                    Ok(()) => {
                        trace!("probe ok");
                        counter!(M_PROBE_OK).increment(1);
                        SupervisorEvent::ProbeOk
                    }
                    Err(e) => {
                        debug!(error = %e, "probe failed");
                        counter!(M_PROBE_FAIL).increment(1);
                        SupervisorEvent::ProbeFailed { reason: e.to_string() }
                    }
                };
                let _ = tx.send(evt).await;
            }
        }
    }
}

async fn probe_once(tunnel: &Tunnel, target: SocketAddr, timeout: Duration) -> Result<(), Error> {
    match tokio::time::timeout(timeout, tunnel.dial_tcp(target)).await {
        Ok(Ok(_conn)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::other(format!("probe timeout after {:?}", timeout))),
    }
}
