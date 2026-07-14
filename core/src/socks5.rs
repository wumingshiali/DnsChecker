//! SOCKS5 客户端握手实现（RFC 1928）。
//!
//! 仅支持无认证模式与 CONNECT 命令，足够用于经代理转发 TCP 握手到 DNS 53 端口。
//! 全程使用 `std::net` 同步 I/O，通过 `connect_timeout` 与读写超时控制阻塞时间，
//! 错误以 `io::Error` 原样返回。

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// 经 SOCKS5 代理建立到 `target` 的 TCP 连接。
///
/// 流程：连代理 → 协商无认证 → 发 CONNECT 请求 → 校验回复 → 返回可用流。
/// 全程受 `timeout` 约束。
pub(crate) fn connect_socks5(
    proxy: SocketAddr,
    target: SocketAddr,
    timeout: Duration,
) -> io::Result<TcpStream> {
    // 1. 连接代理服务器（带超时）
    let mut stream = TcpStream::connect_timeout(&proxy, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // 2. 握手：声明只支持「无认证」方法 (0x00)
    //    报文: VER=0x05, NMETHODS=0x01, METHODS=[0x00]
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut handshake = [0u8; 2];
    stream.read_exact(&mut handshake)?;
    if handshake[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid socks version in handshake: {}", handshake[0]),
        ));
    }
    match handshake[1] {
        0x00 => {} // 无认证，通过
        0xFF => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks5 proxy requires authentication (not supported)",
            ))
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unsupported socks5 auth method: {}", other),
            ))
        }
    }

    // 3. 发送 CONNECT 请求
    //    报文: VER, CMD=0x01, RSV=0x00, ATYP, DST.ADDR, DST.PORT
    let mut req = Vec::with_capacity(22);
    req.push(0x05); // VER
    req.push(0x01); // CMD = CONNECT
    req.push(0x00); // RSV
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(0x01); // ATYP = IPv4
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(0x04); // ATYP = IPv6
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req)?;

    // 4. 读取回复头: VER, REP, RSV, ATYP
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid socks version in reply: {}", header[0]),
        ));
    }
    if header[1] != 0x00 {
        return Err(reply_error(header[1]));
    }
    // 5. 读取并丢弃绑定地址（长度随 ATYP 变化）
    match header[3] {
        0x01 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf)?;
        }
        0x04 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut buf)?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown socks5 reply ATYP: {}", other),
            ))
        }
    }
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;

    Ok(stream)
}

/// 将 SOCKS5 回复码 (REP) 映射为语义对应的 `io::Error`。
fn reply_error(rep: u8) -> io::Error {
    let (kind, msg) = match rep {
        0x01 => (io::ErrorKind::Other, "socks5 general failure"),
        0x02 => (io::ErrorKind::PermissionDenied, "socks5 connection not allowed"),
        0x03 => (io::ErrorKind::NetworkUnreachable, "socks5 network unreachable"),
        0x04 => (io::ErrorKind::HostUnreachable, "socks5 host unreachable"),
        0x05 => (io::ErrorKind::ConnectionRefused, "socks5 connection refused"),
        0x06 => (io::ErrorKind::TimedOut, "socks5 ttl expired"),
        0x07 => (io::ErrorKind::Unsupported, "socks5 command not supported"),
        0x08 => (io::ErrorKind::InvalidData, "socks5 address type not supported"),
        _ => (io::ErrorKind::Other, "socks5 unknown reply code"),
    };
    io::Error::new(kind, format!("{} (rep={:#x})", msg, rep))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_error_maps_known_codes() {
        assert_eq!(reply_error(0x05).kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(reply_error(0x03).kind(), io::ErrorKind::NetworkUnreachable);
        assert_eq!(reply_error(0x06).kind(), io::ErrorKind::TimedOut);
        assert_eq!(reply_error(0x04).kind(), io::ErrorKind::HostUnreachable);
    }

    /// 用本地 mock SOCKS5 服务端验证完整握手流程。
    #[test]
    fn handshake_succeeds_against_mock_server() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let target = "127.0.0.1:53".parse::<SocketAddr>().unwrap();

        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // 读取并校验握手
            let mut hs = [0u8; 3];
            conn.read_exact(&mut hs).unwrap();
            assert_eq!(hs, [0x05, 0x01, 0x00]);
            conn.write_all(&[0x05, 0x00]).unwrap();

            // 读取 CONNECT 请求头，按 ATYP 跳过地址与端口
            let mut header = [0u8; 4];
            conn.read_exact(&mut header).unwrap();
            assert_eq!(header[0], 0x05);
            assert_eq!(header[1], 0x01);
            match header[3] {
                0x01 => {
                    let mut b = [0u8; 4];
                    conn.read_exact(&mut b).unwrap();
                }
                _ => panic!("unexpected atyp"),
            }
            let mut p = [0u8; 2];
            conn.read_exact(&mut p).unwrap();

            // 回复成功: VER, REP=0x00, RSV, ATYP=IPv4, BND.ADDR, BND.PORT
            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });

        let stream = connect_socks5(proxy_addr, target, Duration::from_secs(2)).unwrap();
        drop(stream);
        handle.join().unwrap();
    }

    /// mock 服务端返回 REP=0x05（连接被拒绝）时，应映射为对应错误。
    #[test]
    fn handshake_surfaces_proxy_reject() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let target = "127.0.0.1:53".parse::<SocketAddr>().unwrap();

        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut hs = [0u8; 3];
            conn.read_exact(&mut hs).unwrap();
            conn.write_all(&[0x05, 0x00]).unwrap();
            let mut header = [0u8; 4];
            conn.read_exact(&mut header).unwrap();
            if header[3] == 0x01 {
                let mut b = [0u8; 4];
                conn.read_exact(&mut b).unwrap();
            }
            let mut p = [0u8; 2];
            conn.read_exact(&mut p).unwrap();
            // 回复连接被拒绝
            conn.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });

        let err = connect_socks5(proxy_addr, target, Duration::from_secs(2)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        handle.join().unwrap();
    }
}
