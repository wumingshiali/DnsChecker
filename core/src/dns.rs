//! DNS 查询实现（DNS over TCP，明文，遵循 RFC 1035 / RFC 7766）。
//!
//! 选择 TCP 而非 UDP 传输，以便复用现有 SOCKS5 代理通道（UDP ASSOCIATE 较复杂）。
//! 仅实现 A / AAAA 记录查询，满足解析质量检测需求。错误原样返回。

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
use std::time::Duration;

use crate::addr::{resolve_proxy, resolve_target};
use crate::socks5::connect_socks5;

/// 查询 ID（固定值；单线程顺序查询不会冲突，响应需匹配此 ID）。
const QUERY_ID: u16 = 0x1234;
/// 标志位：RD=1（递归请求）。
const FLAGS_RD: u16 = 0x0100;
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;

/// 解析域名的 A + AAAA 记录，返回所有 IP（IPv4 在前，IPv6 在后）。
///
/// - `doh` 为 `Some(url)` 时通过 DNS over HTTPS（RFC 8484）解析，`dns_server`
///   与 `use_proxy` 被忽略（DoH 走加密 HTTPS 直连，不支持 SOCKS5 转发）。
/// - `doh` 为 `None` 时走明文 DNS over TCP 到 `dns_server`。
///
/// A 查询失败会原样返回错误；AAAA 查询失败被忽略（许多域名没有 IPv6）。
pub fn resolve(
    dns_server: &str,
    domain: &str,
    timeout: Duration,
    proxy: Option<&str>,
    doh: Option<&str>,
) -> io::Result<Vec<IpAddr>> {
    let mut ips = resolve_once(dns_server, domain, QTYPE_A, timeout, proxy, doh)?;
    // AAAA 尽力而为：失败不阻断（域名可能无 IPv6 或网络抖动）
    if let Ok(v6) = resolve_once(dns_server, domain, QTYPE_AAAA, timeout, proxy, doh) {
        ips.extend(v6);
    }
    Ok(ips)
}

/// 单次查询的传输分发：DoH 或明文 TCP。
///
/// DoH 失败时自动回退到明文 TCP（国外 DoH 端点常因网络不可达而失败，
/// 此时用该 DNS 服务器的 TCP 53 兜底，保证可解析）。
fn resolve_once(
    dns_server: &str,
    domain: &str,
    qtype: u16,
    timeout: Duration,
    proxy: Option<&str>,
    doh: Option<&str>,
) -> io::Result<Vec<IpAddr>> {
    match doh {
        Some(url) => {
            // DoH 用较短超时（最多 2s）快速失败，失败回退 TCP 53，
            // 避免国外 DoH 不可达时每个查询都等满 timeout
            let doh_timeout = std::cmp::min(timeout, Duration::from_secs(2));
            query_doh(url, domain, qtype, doh_timeout)
                .or_else(|_| query(dns_server, domain, qtype, timeout, proxy))
        }
        None => query(dns_server, domain, qtype, timeout, proxy),
    }
}

/// 通过 DNS over HTTPS（RFC 8484）查询。
///
/// POST 二进制 DNS 报文到 `doh_url`，Content-Type `application/dns-message`，
/// 响应体即标准 DNS 报文（无 TCP 长度前缀），复用 `parse_answers` 解析。
/// 报文构造与解析逻辑与明文 TCP 完全一致，仅传输层不同。
fn query_doh(
    doh_url: &str,
    domain: &str,
    qtype: u16,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let msg = build_query(domain, qtype);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout(timeout)
        .build();
    let resp = agent
        .post(doh_url)
        .set("Content-Type", "application/dns-message")
        .set("Accept", "application/dns-message")
        .send_bytes(&msg)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut body = Vec::new();
    resp.into_reader().read_to_end(&mut body)?;
    parse_answers(&body, qtype)
}

/// 向指定 DNS 服务器发起单条 TCP 查询，返回该类型的所有 answer IP。
pub fn query(
    dns_server: &str,
    domain: &str,
    qtype: u16,
    timeout: Duration,
    proxy: Option<&str>,
) -> io::Result<Vec<IpAddr>> {
    let server_addr = resolve_target(dns_server)?;
    let proxy = match proxy {
        None => None,
        Some(p) => Some(resolve_proxy(p)?),
    };

    let msg = build_query(domain, qtype);
    // TCP 报文前置 2 字节长度（big-endian）
    let mut tcp_frame = Vec::with_capacity(msg.len() + 2);
    tcp_frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    tcp_frame.extend_from_slice(&msg);

    let mut stream = match proxy {
        None => TcpStream::connect_timeout(&server_addr, timeout)?,
        Some(p) => connect_socks5(p, server_addr, timeout)?,
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    stream.write_all(&tcp_frame)?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response too short",
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;

    parse_answers(&resp, qtype)
}

/// 构造 DNS 查询报文（不含 TCP 长度前缀）。
fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32);
    // Header
    msg.extend_from_slice(&QUERY_ID.to_be_bytes());
    msg.extend_from_slice(&FLAGS_RD.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question
    encode_name(domain, &mut msg);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
    msg
}

/// 把域名编码为 DNS QNAME（每段 label 前置长度字节，末尾 0）。
fn encode_name(domain: &str, out: &mut Vec<u8>) {
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// 在响应缓冲区中跳过（可能压缩的）NAME 字段，推进 `pos`。
fn skip_name(buf: &[u8], pos: &mut usize) -> io::Result<()> {
    loop {
        if *pos >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns name truncated",
            ));
        }
        let len = buf[*pos];
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        // 高 2 位为 11 表示指针（占 2 字节，跳过即结束 NAME）
        if (len & 0xC0) == 0xC0 {
            *pos += 2;
            return Ok(());
        }
        // 普通 label
        *pos += 1 + len as usize;
    }
}

/// 解析响应，提取指定 qtype 的 answer IP。
fn parse_answers(resp: &[u8], qtype: u16) -> io::Result<Vec<IpAddr>> {
    let id = u16::from_be_bytes([resp[0], resp[1]]);
    if id != QUERY_ID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response id mismatch",
        ));
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(rcode_error(rcode));
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        skip_name(resp, &mut pos)?;
        pos += 4; // QTYPE(2) + QCLASS(2)
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        skip_name(resp, &mut pos)?;
        if pos + 10 > resp.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns answer truncated",
            ));
        }
        let atype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        pos += 2; // TYPE
        pos += 2; // CLASS
        pos += 4; // TTL
        let rdlength = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
        pos += 2;
        if pos + rdlength > resp.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns rdata truncated",
            ));
        }
        // 仅收集与请求类型匹配的记录（自动跳过 CNAME 等）
        if atype == qtype {
            match qtype {
                QTYPE_A if rdlength == 4 => {
                    ips.push(IpAddr::V4(Ipv4Addr::new(
                        resp[pos],
                        resp[pos + 1],
                        resp[pos + 2],
                        resp[pos + 3],
                    )));
                }
                QTYPE_AAAA if rdlength == 16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&resp[pos..pos + 16]);
                    ips.push(IpAddr::V6(Ipv6Addr::from(b)));
                }
                _ => {}
            }
        }
        pos += rdlength;
    }
    Ok(ips)
}

/// 将 DNS RCODE 映射为语义对应的 `io::Error`。
fn rcode_error(rcode: u16) -> io::Error {
    let (kind, msg) = match rcode {
        1 => (io::ErrorKind::InvalidData, "dns format error"),
        2 => (io::ErrorKind::Other, "dns server failure"),
        3 => (io::ErrorKind::AddrNotAvailable, "dns name does not exist"),
        4 => (io::ErrorKind::Unsupported, "dns not implemented"),
        5 => (io::ErrorKind::PermissionDenied, "dns query refused"),
        _ => (io::ErrorKind::Other, "dns unknown rcode"),
    };
    io::Error::new(kind, format!("{} (rcode={})", msg, rcode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_name_basic() {
        let mut out = Vec::new();
        encode_name("qq.com", &mut out);
        assert_eq!(
            out,
            vec![0x02, b'q', b'q', 0x03, b'c', b'o', b'm', 0x00]
        );
    }

    #[test]
    fn encode_name_ignores_trailing_dot() {
        let mut out = Vec::new();
        encode_name("a.b.", &mut out);
        assert_eq!(out, vec![0x01, b'a', 0x01, b'b', 0x00]);
    }

    #[test]
    fn parse_single_a_record() {
        let resp = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x02, b'q', b'q', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
        ];
        let ips = parse_answers(&resp, QTYPE_A).unwrap();
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_multiple_a_records() {
        let resp = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x02, b'q', b'q', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        let ips = parse_answers(&resp, QTYPE_A).unwrap();
        assert_eq!(ips.len(), 2);
    }

    /// 响应中含 CNAME + A 时，应跳过 CNAME 只收集 A。
    #[test]
    fn parse_skips_cname_and_collects_a() {
        let resp = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // question: foo.bar A IN
            0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // answer 1: CNAME -> baz.
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0x03, b'b', b'a', b'z', 0x00,
            // answer 2: A -> 10.0.0.1
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x0A, 0x00, 0x00, 0x01,
        ];
        let ips = parse_answers(&resp, QTYPE_A).unwrap();
        assert_eq!(ips, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_aaaa_record() {
        let resp = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x02, b'q', b'q', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x1c, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let ips = parse_answers(&resp, QTYPE_AAAA).unwrap();
        assert_eq!(ips.len(), 1);
        assert!(ips[0].is_ipv6());
    }

    /// NXDOMAIN（rcode=3）应映射为 AddrNotAvailable。
    #[test]
    fn parse_nxdomain() {
        let resp = vec![
            0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let err = parse_answers(&resp, QTYPE_A).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    }

    /// 用 mock DNS over TCP 服务端验证完整查询路径。
    #[test]
    fn query_against_mock_server() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut len_buf = [0u8; 2];
            conn.read_exact(&mut len_buf).unwrap();
            let qlen = u16::from_be_bytes(len_buf) as usize;
            let mut q = vec![0u8; qlen];
            conn.read_exact(&mut q).unwrap();
            // 校验查询的 QNAME 是 qq.com
            assert_eq!(&q[12..20], &[0x02, b'q', b'q', 0x03, b'c', b'o', b'm', 0x00]);
            let resp = vec![
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x02, b'q', b'q', 0x03, b'c', b'o', b'm', 0x00,
                0x00, 0x01, 0x00, 0x01,
                0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x08, 0x08, 0x08, 0x08,
            ];
            conn.write_all(&(resp.len() as u16).to_be_bytes()).unwrap();
            conn.write_all(&resp).unwrap();
        });

        let server = format!("127.0.0.1:{}", port);
        let ips = query(&server, "qq.com", QTYPE_A, Duration::from_secs(2), None).unwrap();
        assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        handle.join().unwrap();
    }

    /// 端到端 DoH 测试：用腾讯公共 DoH 解析 qq.com 的 A 记录。
    /// 默认需联网，用 `--ignored` 手动运行。
    #[test]
    #[ignore = "requires network access to a public DoH server"]
    fn query_doh_real_alidns() {
        let ips = query_doh(
            "https://doh.pub/dns-query",
            "qq.com",
            QTYPE_A,
            Duration::from_secs(15),
        )
        .unwrap();
        assert!(!ips.is_empty(), "should resolve at least one IP");
        assert!(ips.iter().all(|ip| ip.is_ipv4()), "A records should be IPv4");
    }
}
