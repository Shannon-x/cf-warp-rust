//! 把 SIGINT/SIGTERM 转换成 CancellationToken。

use tokio_util::sync::CancellationToken;

/// 启动一个后台任务，监听信号；收到时翻转 token，触发全局停机。
pub fn install(token: CancellationToken) {
    tokio::spawn(async move {
        match wait_for_signal().await {
            Ok(()) => tracing::info!("shutdown signal received"),
            Err(e) => tracing::error!(error = %e, "signal handler failed; shutting down safely"),
        }
        token.cancel();
    });
}

#[cfg(unix)]
async fn wait_for_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => tracing::debug!("SIGTERM"),
        _ = sigint.recv()  => tracing::debug!("SIGINT"),
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}
