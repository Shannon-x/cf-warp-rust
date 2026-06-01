//! 监听 `config.toml`，把变化事件汇报到日志。
//!
//! v1 行为：检测到变化后重新解析整个文件，成功就写一条 INFO，失败就写一条
//! WARN。**不主动改 running state** —— 因为大部分非平凡设置（监听地址、日志
//! 级别、探针间隔）热改都涉及子系统重启，会让生命周期复杂化。这里的价值
//! 是：你改错配置文件能立刻在日志里看到，不必等到重启时才发现。

use crate::config::Config;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// 启动一个后台任务监听 `config_path` 的写入事件，立即返回。`cancel` 触发
/// 或 watcher 自身退出时，任务也随之结束。
pub fn spawn(config_path: PathBuf, cancel: CancellationToken) {
    tokio::spawn(async move {
        if let Err(e) = run(config_path, cancel).await {
            warn!(error = %e, "config watcher exited with error");
        }
    });
}

async fn run(config_path: PathBuf, cancel: CancellationToken) -> notify::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<Event>>();

    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<Event>| {
            // notify 的回调不在 tokio 线程上执行
            let _ = tx.send(res);
        })?;

    let dir = config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    watcher.watch(&dir, RecursiveMode::NonRecursive)?;
    info!(path = %config_path.display(), "watching config for changes");

    // 去抖：很多编辑器在保存时会触发多个 write/create/rename 事件，需要合并
    let debounce = Duration::from_millis(250);
    let mut last_kicked = std::time::Instant::now() - debounce;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!("config watcher stopping");
                return Ok(());
            }
            evt = rx.recv() => {
                let evt = match evt {
                    Some(Ok(e)) => e,
                    Some(Err(e)) => { warn!(error = %e, "notify error"); continue; }
                    None => return Ok(()),
                };
                let target_changed = evt.paths.iter().any(|p| p == &config_path);
                let is_write = matches!(
                    evt.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                );
                if !(target_changed && is_write) { continue; }

                if last_kicked.elapsed() < debounce { continue; }
                last_kicked = std::time::Instant::now();

                // 给那些先 rename 后 write 的编辑器留一点空档
                tokio::time::sleep(Duration::from_millis(100)).await;
                match Config::load(Some(&config_path)) {
                    Ok(_) => info!(path = %config_path.display(),
                        "config file changed and parses OK (restart to apply non-trivial fields)"),
                    Err(e) => warn!(path = %config_path.display(), error = %e,
                        "config file changed but failed to parse — leaving running state alone"),
                }
            }
        }
    }
}
