//! SOCKS5 前端。CONNECT 与 UDP ASSOCIATE 都共用同一个 `Tunnel`。

pub mod tcp;
pub mod udp;

pub use tcp::{bind_listener, serve};
