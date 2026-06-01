//! Prometheus 指标暴露层。
//!
//! 通过 `metrics` facade 注入指标，调用点不需要知道 exporter；`serve` 在
//! 启动时挂上 `metrics-exporter-prometheus`，并用 axum 提供 `/metrics`。

use crate::config::MetricsConfig;
use crate::error::{Error, Result};
use axum::{routing::get, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ── 指标命名集中放这里，调用点写起来短 ─────────────────────────────────────
pub const M_CONNS_OPENED: &str = "warp_rust_conns_opened_total";
pub const M_CONNS_CLOSED: &str = "warp_rust_conns_closed_total";
pub const M_BYTES_UP: &str = "warp_rust_bytes_up_total";
pub const M_BYTES_DOWN: &str = "warp_rust_bytes_down_total";
pub const M_PROBE_OK: &str = "warp_rust_probe_success_total";
pub const M_PROBE_FAIL: &str = "warp_rust_probe_failure_total";
pub const M_TUNNEL_REBUILD: &str = "warp_rust_tunnel_rebuild_total";
pub const M_REREGISTER: &str = "warp_rust_reregister_total";
pub const M_ROTATE: &str = "warp_rust_rotate_identity_total";
pub const M_UDP_ASSOCIATES_ACTIVE: &str = "warp_rust_udp_associates_active";

/// 装配 Prometheus exporter，在 `cfg.bind` 上启动一个 axum 服务。正常停机时
/// 返回 Ok(())。
pub async fn serve(cfg: MetricsConfig, cancel: CancellationToken) -> Result<()> {
    if !cfg.enabled {
        info!("metrics disabled in config");
        return Ok(());
    }

    let handle: PrometheusHandle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| Error::other(format!("install prometheus recorder: {e}")))?;

    let app = Router::new()
        .route("/metrics", get(move || render(handle.clone())))
        .route("/healthz", get(|| async { "ok" }));

    let addr: SocketAddr = cfg.bind;
    info!(%addr, "metrics endpoint listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let serve =
        axum::serve(listener, app).with_graceful_shutdown(async move { cancel.cancelled().await });

    if let Err(e) = serve.await {
        warn!(error = %e, "metrics server exited with error");
    }
    Ok(())
}

async fn render(handle: PrometheusHandle) -> String {
    handle.render()
}
