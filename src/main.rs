//! warp-rust —— 通过 Cloudflare WARP 长期常驻的 SOCKS5 代理。
//!
//! 启动序列：解析配置 → 初始化日志 → 安装信号处理 → 加载/注册 WARP 账号
//! → 建立 WireGuard 隧道 → 启动 SOCKS5 监听 → 启动 supervisor →
//! 启动 metrics 服务 → 启动配置热重载 watcher → 等待 cancel token。

mod config;
mod config_watch;
mod error;
mod health;
mod metrics;
mod proxy;
mod signals;
mod supervisor;
mod telemetry;
mod tunnel;
mod warp;

use crate::config::Config;
use crate::error::Result;
use crate::supervisor::Supervisor;
use crate::tunnel::Tunnel;
use crate::warp::{AccountManager, IdentityPool};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use wireguard_netstack::ManagedTunnel;

#[derive(Debug, Parser)]
#[command(name = "warp-rust", about = "SOCKS5 proxy through Cloudflare WARP")]
struct Cli {
    /// 配置文件路径。默认 ./config.toml
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("fatal: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let cfg = Config::load(Some(&cli.config))?;
    telemetry::init(&cfg.logging);

    info!(version = env!("CARGO_PKG_VERSION"), config = %cli.config.display(), "warp-rust starting");

    let cancel = CancellationToken::new();
    signals::install(cancel.clone());

    // 1. 加载凭据；若未注册则向 Cloudflare 申请新身份
    let account = Arc::new(AccountManager::new(cfg.warp.clone()));
    let snapshot = account.load_or_register().await?;

    // 2. 起 WireGuard 隧道
    info!(
        tunnel_ip = %snapshot.wg_config.tunnel_ip,
        peer = %snapshot.wg_config.peer_endpoint,
        "connecting WireGuard tunnel"
    );
    let managed = ManagedTunnel::connect(snapshot.wg_config.clone()).await?;
    let tunnel = Tunnel::from_managed(managed);

    // 3. 加载身份池（为空也允许）
    let identity_pool = IdentityPool::load(&cfg.warp.data_dir)?;

    // 4. 启动 SOCKS5 监听
    let server_cfg = cfg.server.clone();
    let socks_cancel = cancel.clone();
    let socks_tunnel = tunnel.clone();
    let socks_task = tokio::spawn(async move {
        if let Err(e) = proxy::serve(server_cfg, socks_tunnel, socks_cancel).await {
            error!(error = %e, "SOCKS5 server exited with error");
        }
    });

    // 5. 启动 supervisor（健康探针、恢复阶梯、配置刷新定时器）
    let supervisor = Supervisor::new(
        cfg.clone(),
        account.clone(),
        tunnel.clone(),
        identity_pool,
        snapshot.credentials,
    );
    let supervisor_cancel = cancel.clone();
    let supervisor_task = tokio::spawn({
        let sup = supervisor.clone();
        async move {
            if let Err(e) = sup.run(supervisor_cancel).await {
                error!(error = %e, "supervisor exited with error");
            }
        }
    });

    // 6. metrics 端点
    let metrics_cfg = cfg.metrics.clone();
    let metrics_cancel = cancel.clone();
    let metrics_task = tokio::spawn(async move {
        if let Err(e) = metrics::serve(metrics_cfg, metrics_cancel).await {
            error!(error = %e, "metrics server exited with error");
        }
    });

    // 7. 配置文件热重载 watcher
    info!(hot_reload_enabled = cfg.hot_reload.enabled, "hot reload status");
    if cfg.hot_reload.enabled {
        let abs_path = std::fs::canonicalize(&cli.config).unwrap_or_else(|_| cli.config.clone());
        config_watch::spawn(abs_path, cancel.clone());
    }

    // 8. 等待停机信号
    cancel.cancelled().await;
    info!("shutdown initiated");

    // 9. 排空子任务
    let _ = tokio::time::timeout(Duration::from_secs(5), socks_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), supervisor_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), metrics_task).await;
    tunnel.clear();
    info!("warp-rust stopped");
    Ok(())
}
