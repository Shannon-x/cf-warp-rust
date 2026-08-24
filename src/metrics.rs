//! Prometheus 指标暴露层。
//!
//! 通过 `metrics` facade 注入指标，调用点不需要知道 exporter；`serve` 在
//! 启动时挂上 `metrics-exporter-prometheus`，并用 axum 提供 `/metrics`。

use crate::config::MetricsConfig;
use crate::error::{Error, Result};
use axum::{http::StatusCode, routing::get, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ── 指标命名集中放这里，调用点写起来短 ─────────────────────────────────────
pub const M_CONNS_OPENED: &str = "warp_rust_conns_opened_total";
pub const M_CONNS_CLOSED: &str = "warp_rust_conns_closed_total";
pub const M_BYTES_UP: &str = "warp_rust_bytes_up_total";
pub const M_BYTES_DOWN: &str = "warp_rust_bytes_down_total";
pub const M_PROBE_OK: &str = "warp_rust_probe_success_total";
pub const M_PROBE_FAIL: &str = "warp_rust_probe_failure_total";
/// 单个探针目标失败计数（带 target 标签）。即使整轮 quorum 达标也会累计，
/// 用于发现「某上游被选择性阻断而整体仍判健康」的情况。
pub const M_PROBE_TARGET_FAIL: &str = "warp_rust_probe_target_failure_total";
pub const M_TUNNEL_REBUILD: &str = "warp_rust_tunnel_rebuild_total";
/// WireGuard 会话陈旧（超过重握手周期仍无成功握手）被健康探针判定为不健康的次数。
pub const M_HANDSHAKE_STALE: &str = "warp_rust_handshake_stale_total";
/// 「拨号探针通过、但业务出口成功率过低」这一选择性故障被判定的次数。
///
/// 这个指标持续增长意味着探针目标可达而业务目标不可达——要么出口被对端选择性
/// 屏蔽，要么探针目标选得不能代表业务路径。
pub const M_EGRESS_DEGRADED: &str = "warp_rust_egress_degraded_total";
/// 达到 max_concurrent_connections 而被拒的连接中，因日志限速被抑制的条数。
pub const M_CONNS_REJECTED_LOG_SUPPRESSED: &str = "warp_rust_conns_rejected_log_suppressed_total";
/// 实际下发给 WireGuard 隧道的 MTU。让「配置到底生效没有」在运行期可验证，
/// 而不是只能靠安装脚本那两行一闪而过的 warn。
pub const M_EFFECTIVE_MTU: &str = "warp_rust_effective_mtu";
pub const M_ACTIVE_TUNNEL_GENERATIONS: &str = "warp_rust_active_tunnel_generations";
pub const M_TUNNEL_GENERATIONS_FORCED_RETIRE: &str =
    "warp_rust_tunnel_generation_forced_retire_total";
pub const M_REREGISTER: &str = "warp_rust_reregister_total";
pub const M_ROTATE: &str = "warp_rust_rotate_identity_total";
pub const M_UDP_ASSOCIATES_ACTIVE: &str = "warp_rust_udp_associates_active";
/// client→tunnel 方向在入队前被丢弃的客户端报文数，带 `reason` label
/// （`queue_full` / `oversized`）。
///
/// 这个指标存在的意义：转发侧（域名解析 + 隧道回压等待）可能 await 很久，
/// 如果直接在 recv 循环里 await，丢包会发生在**内核** socket buffer 里——
/// 完全不可观测。把丢包点搬到我们自己的有界队列后，回压才是可度量的。
pub const M_UDP_CLIENT_RX_DROPPED: &str = "warp_rust_udp_client_rx_dropped_total";
// v0.1.1：DoS 防护与 DNS 解析相关
pub const M_CONNS_REJECTED: &str = "warp_rust_conns_rejected_total";
pub const M_CONNS_REJECTED_UNHEALTHY: &str = "warp_rust_conns_rejected_tunnel_unhealthy_total";
pub const M_CONNS_REJECTED_DIAL_PRESSURE: &str = "warp_rust_conns_rejected_dial_pressure_total";
pub const M_HANDSHAKE_TIMEOUT: &str = "warp_rust_handshake_timeout_total";
pub const M_IDLE_TIMEOUT: &str = "warp_rust_idle_timeout_total";
pub const M_AUTH_FAIL: &str = "warp_rust_auth_fail_total";
pub const M_DNS_CACHE_HIT: &str = "warp_rust_dns_cache_hit_total";
pub const M_DNS_QUERY: &str = "warp_rust_dns_query_total";
pub const M_DNS_QUERY_FAIL: &str = "warp_rust_dns_query_failure_total";
// v0.3.x：DNS 负缓存 + singleflight
pub const M_DNS_SINGLEFLIGHT_DEDUP: &str = "warp_rust_dns_singleflight_dedup_total";
pub const M_DNS_NEGATIVE_CACHE_HIT: &str = "warp_rust_dns_negative_cache_hit_total";
// v0.3.x：容器内 0.0.0.0 + 无 auth 放行时的警告计数（聚合后可触发告警）
pub const M_CONTAINER_OPEN_PROXY_WARN: &str = "warp_rust_container_open_proxy_warn_total";
// v0.3.2：任何「未鉴权 + 非 loopback 仍被放行」的统一计数器，覆盖两条路径：
//   · WARP_RUST_ALLOW_OPEN_PROXY=1（显式 escape hatch）
//   · 容器 + 0.0.0.0 + WARP_RUST_TRUSTED_HOST_NET=1（容器例外）
// 命名与同模块其它 counter 一致：动作（_allowed）而非程度（_risk）。
// 单条 Prometheus 告警 `increase(warp_rust_open_proxy_allowed_total[5m]) > 0`
// 即可监听全部高风险放行姿势。
pub const M_OPEN_PROXY_ALLOWED: &str = "warp_rust_open_proxy_allowed_total";
pub const M_DIAL_ATTEMPT: &str = "warp_rust_dial_attempt_total";
pub const M_DIAL_FAILURE: &str = "warp_rust_dial_failure_total";
pub const M_DIAL_TIMEOUT: &str = "warp_rust_dial_timeout_total";

/// 在启动期最早安装 recorder，使配置安全校验和隧道初始化阶段
/// 产生的 counter/gauge 不会在 HTTP 服务开始前丢失。
pub fn install_recorder() -> Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| Error::other(format!("install prometheus recorder: {e}")))
}

/// 装配 Prometheus exporter，在 `cfg.bind` 上启动一个 axum 服务。正常停机时
/// 返回 Ok(())。
pub async fn serve(
    cfg: MetricsConfig,
    cancel: CancellationToken,
    healthy: Arc<AtomicBool>,
    handle: PrometheusHandle,
) -> Result<()> {
    if !cfg.enabled {
        info!("metrics disabled in config");
        return Ok(());
    }

    let app = Router::new()
        .route("/metrics", get(move || render(handle.clone())))
        .route("/livez", get(|| async { "ok" }))
        .route(
            "/healthz",
            get(move || {
                let healthy = healthy.clone();
                async move {
                    if healthy.load(Ordering::Acquire) {
                        (StatusCode::OK, "ok")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "tunnel unhealthy")
                    }
                }
            }),
        );

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
