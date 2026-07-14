//! DnsChecker 核心库
//!
//! 提供 DNS 服务器 ping（连通性与往返延迟测量）与解析质量检测相关功能。
//! DNS 查询与 ping 均走 TCP 53 端口，可选 SOCKS5 代理转发，兼容 IPv4 与 IPv6。

#![forbid(unsafe_code)]

pub mod addr;
pub mod dns;
pub mod ping;
pub mod quality;
pub mod score;
pub mod socks5;

pub use ping::{ping_dns, ping_dns_multi, ping_dns_with_proxy, PingStat, DEFAULT_SOCKS5_PROXY};
pub use quality::{
    check_resolve_quality, check_resolve_quality_for, QualityReport, QualitySample,
    ResolveFailure, QUALITY_DOMAINS,
};
pub use score::{compute_score, Encryption};

/// DNS 协议默认端口
pub const DNS_PORT: u16 = 53;

/// 库版本信息，与 Cargo.toml 中的版本保持同步
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
