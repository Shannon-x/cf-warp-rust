//! warp-rust —— 通过 Cloudflare WARP 长期常驻的 SOCKS5 代理。
//!
//! 启动序列：解析配置 → 初始化日志 → 安装信号处理 → 加载/注册 WARP 账号
//! → 建立 WireGuard 隧道 → 启动 SOCKS5 监听 → 启动 supervisor →
//! 启动 metrics 服务 → 启动配置热重载 watcher → 等待 cancel token。

mod config;
mod config_watch;
mod dns;
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
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(
    name = "warp-rust",
    version,
    about = "SOCKS5 proxy through Cloudflare WARP"
)]
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

    // 在 validate/隧道初始化前安装，否则开放代理等启动期安全计数会丢失。
    let metrics_handle = if cfg.metrics.enabled {
        Some(metrics::install_recorder()?)
    } else {
        None
    };

    // 启动前安全校验：拒绝公网+无鉴权组合等高危配置
    if let Err(msg) = cfg.validate() {
        eprintln!("\n{msg}\n");
        return Err(crate::error::Error::Config(msg));
    }

    let cancel = CancellationToken::new();
    signals::install(cancel.clone());

    // 0. 先占好 SOCKS5 端口，再做任何昂贵操作。端口被占用/特权端口是最常见的
    //    部署事故；提前绑定可让这类错误在 <1s 内以可操作信息失败，而不是每次
    //    重启都先跑一遍 WARP 注册 API + WireGuard 握手再失败（既慢又刷账号）。
    let socks_listener = proxy::bind_listener(cfg.server.bind).await?;

    // 1. 加载凭据；若未注册则向 Cloudflare 申请新身份
    let account = Arc::new(AccountManager::new(cfg.warp.clone()));
    let snapshot = account.load_or_register().await?;

    // 2. 起 WireGuard 隧道
    info!(
        tunnel_ip = %snapshot.wg_config.tunnel_ip,
        peer = %snapshot.wg_config.peer_endpoint,
        "connecting WireGuard tunnel"
    );
    let connected = Tunnel::connect_candidate(snapshot.wg_config.clone()).await?;
    let active_wg_config = connected.config;
    let tunnel = Tunnel::from_managed(connected.managed);

    // 3. 加载身份池（为空也允许）
    let identity_pool = IdentityPool::load(&cfg.warp.data_dir)?;

    // 4. 先构造 supervisor。健康标志初始为 false；首次公网探针成功前，
    // SOCKS5 只完成协议握手并快速返回 GeneralFailure，不再为注定失败的请求
    // 批量分配 smoltcp socket buffer。隧道失联期间这能切断客户端重试风暴。
    let supervisor = Supervisor::new(
        cfg.clone(),
        account.clone(),
        tunnel.clone(),
        identity_pool,
        snapshot.credentials,
        active_wg_config,
    );
    let health_flag = supervisor.health_flag();

    let mut services = tokio::task::JoinSet::new();
    let supervisor_cancel = cancel.clone();
    services.spawn({
        let sup = supervisor.clone();
        async move { ("supervisor", sup.run(supervisor_cancel).await) }
    });

    // 5. 启动 SOCKS5 监听（带 DoS 防护 + DNS 解析层）
    let server_cfg = cfg.server.clone();
    let limits = cfg.limits.clone();
    let resolver = Arc::new(crate::dns::Resolver::new(&cfg.dns, tunnel.clone()));
    let socks_cancel = cancel.clone();
    let socks_tunnel = tunnel.clone();
    let socks_health = health_flag.clone();
    services.spawn(async move {
        (
            "SOCKS5",
            proxy::serve(
                socks_listener,
                server_cfg,
                limits,
                resolver,
                socks_tunnel,
                socks_health,
                socks_cancel,
            )
            .await,
        )
    });

    // 6. metrics 端点
    let metrics_cfg = cfg.metrics.clone();
    let metrics_cancel = cancel.clone();
    if let Some(metrics_handle) = metrics_handle {
        services.spawn(async move {
            (
                "metrics",
                metrics::serve(metrics_cfg, metrics_cancel, health_flag, metrics_handle).await,
            )
        });
    }

    // 7. 配置文件热重载 watcher
    info!(
        hot_reload_enabled = cfg.hot_reload.enabled,
        "hot reload status"
    );
    if cfg.hot_reload.enabled {
        let abs_path = std::fs::canonicalize(&cli.config).unwrap_or_else(|_| cli.config.clone());
        config_watch::spawn(abs_path, cancel.clone());
    }

    // 8. 等待停机信号；任一关键服务意外退出也必须让主进程失败退出，交给
    // systemd 重启。旧实现只记一条日志后继续假装健康，监听 bind 失败时尤其危险。
    let unexpected = tokio::select! {
        _ = cancel.cancelled() => None,
        joined = services.join_next() => {
            match joined {
                Some(Ok((name, Ok(())))) => Some(format!("{name} service exited unexpectedly")),
                Some(Ok((name, Err(e)))) => Some(format!("{name} service failed: {e}")),
                Some(Err(e)) => Some(format!("service task failed: {e}")),
                None => Some("all services exited unexpectedly".to_owned()),
            }
        }
    };
    cancel.cancel();
    info!("shutdown initiated");

    // 9. 排空子任务
    let drain = async {
        while let Some(result) = services.join_next().await {
            if let Err(e) = result {
                warn!(error = ?e, "service task did not stop cleanly");
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .is_err()
    {
        warn!("service shutdown grace expired; aborting remaining tasks");
        services.shutdown().await;
    }
    tunnel.clear();
    info!("warp-rust stopped");
    if let Some(message) = unexpected {
        Err(crate::error::Error::other(message))
    } else {
        Ok(())
    }
}
