//! 目标地址解析，统一处理 IPv4/IPv6/主机名/带端口等多种输入形式。

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::DNS_PORT;

/// 把用户输入的目标地址解析为 [`SocketAddr`]。
///
/// 支持以下形式（自动兼容 IPv4 与 IPv6）：
/// - 带端口的字面地址：`8.8.8.8:53` / `[::1]:53`
/// - 裸 IPv4：`8.8.8.8`（自动补端口 53）
/// - 裸 IPv6：`::1` / `2001:4860:4860::8888`（自动补端口 53）
/// - 主机名：`dns.google`（自动补端口 53，交由系统解析）
///
/// 解析失败时原样返回底层 I/O 错误。
pub(crate) fn resolve_target(target: &str) -> io::Result<SocketAddr> {
    // 1. 带端口的字面 SocketAddr，如 "8.8.8.8:53" / "[::1]:53"
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // 2. 裸 IP（IPv4 或 IPv6），补默认 DNS 端口
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }
    // 3. 主机名，补端口后交由系统解析
    let with_port = format!("{}:{}", target, DNS_PORT);
    with_port.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no address resolved for target: {}", target),
        )
    })
}

/// 解析 SOCKS5 代理地址（必须自带端口，如 `127.0.0.1:1080`）。
pub(crate) fn resolve_proxy(proxy: &str) -> io::Result<SocketAddr> {
    proxy.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid proxy address: {}", proxy),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn resolve_bare_ipv4_gets_default_port() {
        let a = resolve_target("8.8.8.8").unwrap();
        assert_eq!(a.port(), DNS_PORT);
        assert_eq!(a.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn resolve_bare_ipv6_gets_default_port() {
        let a = resolve_target("::1").unwrap();
        assert_eq!(a.port(), DNS_PORT);
        assert!(a.is_ipv6());
    }

    #[test]
    fn resolve_full_ipv6_gets_default_port() {
        let a = resolve_target("2001:4860:4860::8888").unwrap();
        assert_eq!(a.port(), DNS_PORT);
        assert!(a.is_ipv6());
    }

    #[test]
    fn resolve_ipv4_with_explicit_port() {
        let a = resolve_target("8.8.8.8:5353").unwrap();
        assert_eq!(a.port(), 5353);
    }

    #[test]
    fn resolve_ipv6_with_explicit_port() {
        let a = resolve_target("[::1]:5353").unwrap();
        assert_eq!(a.port(), 5353);
        assert!(a.is_ipv6());
    }

    #[test]
    fn resolve_proxy_requires_port() {
        // 带端口的代理地址可正常解析
        assert!(resolve_proxy("127.0.0.1:1080").is_ok());
        // 不带端口的无法解析为 SocketAddr
        assert!(resolve_proxy("127.0.0.1").is_err());
    }
}
