//! 跨模块统一错误类型。各子模块的具体错误通过 `From` 向上汇聚到这里。

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("warp registration: {0}")]
    WarpApi(#[from] warp_wireguard_gen::Error),

    #[error("wireguard netstack: {0}")]
    Netstack(#[from] wireguard_netstack::Error),

    #[error("tunnel not ready")]
    TunnelNotReady,

    #[error("DNS lookup returned no IPv4 result for {0}")]
    DnsNoIpv4(String),

    #[error("SOCKS5: {0}")]
    Socks(#[from] fast_socks5::SocksError),

    #[error("SOCKS5 server: {0}")]
    SocksServer(#[from] fast_socks5::server::SocksServerError),

    #[error("upstream dial failed for {addr}: {source}")]
    Dial {
        addr: SocketAddr,
        #[source]
        source: Box<wireguard_netstack::Error>,
    },

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML: {0}")]
    Toml(#[from] toml::de::Error),

    // figment::Error 大小 208 B（实测 aarch64-apple-darwin，dev profile）。直接放进
    // enum 会让 Error 整体 ≥240 B，触发 clippy::result_large_err（默认阈值 128 B）。
    // 这里 Box 起来后整个 Error 降到 ≈96 B（最大变体 toml::de::Error = 88 B）。
    //
    // 注：thiserror 的 `#[from]` 在字段类型为 `Box<E>` 时只会生成 `From<Box<E>>`，
    // 不会生成 `From<E>`。为了让现有 `?` 调用点（main.rs::run、config_watch.rs::
    // watch_task）仍然能直接对 `figment::Error` 用 `?`，我们在下面手写一个
    // `From<figment::Error> for Error`，里面做 Box。
    #[error("figment: {0}")]
    Figment(#[source] Box<figment::Error>),

    #[error("{0}")]
    Other(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

// 手写 `From<figment::Error>`：上面 Figment 变体改用了 `Box<figment::Error>` + `#[source]`，
// thiserror 此时只会生成 `From<Box<figment::Error>> for Error`。我们仍然希望像之前那样
// 直接对裸的 `figment::Error` 用 `?`（避免散落到调用点的手工 Box::new），所以补一个
// 从原始类型转过来的 impl，转换时做 Box。
//
// 这是 thiserror 官方文档里推荐的「大 source 错误 Box 化」标准写法。
impl From<figment::Error> for Error {
    fn from(e: figment::Error) -> Self {
        Error::Figment(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归测试：clippy::result_large_err 默认阈值是 128 字节。把 Error 大小钉死在
    /// ≤128B，未来谁再往 enum 里塞一个大 source error（>128B 或多个不 Box 的中型 source）
    /// 都会被这个测试当场抓住，强制走 Box 路径。
    #[test]
    fn error_enum_size_under_clippy_threshold() {
        let sz = std::mem::size_of::<Error>();
        assert!(
            sz <= 128,
            "Error enum 已 {sz} 字节 > 128B，会触发 clippy::result_large_err；\
             请把新加的大变体（>128B 的 source error）改成 Box<…>"
        );
    }

    /// 回归测试：确保对裸 `figment::Error` 仍然能用 `?` —— 也就是 `From<figment::Error>`
    /// 这条手写转换还在。若有人后来把它误删（误以为 thiserror 自动生成），
    /// 这个测试就编译失败。
    #[test]
    fn figment_error_converts_via_question_mark() {
        fn use_q_mark() -> Result<(), Error> {
            // 故意构造一个 figment::Error：从一个无法解析成 SocketAddr 的 string extract。
            let bad: std::result::Result<std::net::SocketAddr, figment::Error> =
                figment::Figment::new()
                    .merge(figment::providers::Serialized::default("v", "not-a-socket"))
                    .extract_inner("v");
            let _ = bad?;
            Ok(())
        }
        let err = use_q_mark().unwrap_err();
        assert!(matches!(err, Error::Figment(_)));
        // 顺带验证 Display 仍然带 figment: 前缀
        assert!(format!("{err}").starts_with("figment:"));
    }
}
