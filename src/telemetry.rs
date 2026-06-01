//! tracing_subscriber 初始化。

use crate::config::{LogFormat, LoggingConfig};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init(cfg: &LoggingConfig) {
    // 设置了 RUST_LOG 时优先用环境变量，否则用 config.toml 中的 level
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    let registry = tracing_subscriber::registry().with(filter);

    match cfg.format {
        LogFormat::Pretty => {
            registry.with(fmt::layer().with_target(true)).init();
        }
        LogFormat::Compact => {
            registry.with(fmt::layer().compact().with_target(true)).init();
        }
        LogFormat::Json => {
            registry
                .with(fmt::layer().json().with_target(true).with_current_span(false))
                .init();
        }
    }
}
