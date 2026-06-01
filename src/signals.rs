//! 把 SIGINT/SIGTERM 转换成 CancellationToken。

use tokio_util::sync::CancellationToken;

/// 启动一个后台任务，监听信号；收到时翻转 token，触发全局停机。
pub fn install(token: CancellationToken) {
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received");
        token.cancel();
    });
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => tracing::debug!("SIGTERM"),
        _ = sigint.recv()  => tracing::debug!("SIGINT"),
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
