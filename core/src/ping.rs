//! DNS 服务器 ping 实现。
//!
//! 通过 TCP 握手到 DNS 服务器的 53 端口测量往返延迟，兼容 IPv4 与 IPv6，
//! 可选经 SOCKS5 代理转发，支持多次采样与统计。错误原样向上返回。

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::addr::{resolve_proxy, resolve_target};
use crate::socks5::connect_socks5;

/// 默认 SOCKS5 代理地址（本机 1080 端口，常见代理客户端默认值）。
pub const DEFAULT_SOCKS5_PROXY: &str = "127.0.0.1:1080";

/// ping 一个 DNS 服务器，返回单次 TCP 握手到 53 端口的往返延迟。
///
/// - `target`: DNS 服务器地址，支持裸 IPv4/IPv6、带端口地址或主机名
/// - `use_proxy`: 是否经 SOCKS5 代理转发（使用 [`DEFAULT_SOCKS5_PROXY`]）
/// - `timeout`: 连接超时
///
/// 任何错误均原样返回，不做包装。
pub fn ping_dns(target: &str, use_proxy: bool, timeout: Duration) -> io::Result<Duration> {
    let proxy = if use_proxy {
        Some(DEFAULT_SOCKS5_PROXY)
    } else {
        None
    };
    ping_dns_with_proxy(target, proxy, timeout)
}

/// 带自定义 SOCKS5 代理地址的单次 ping。`proxy` 为 [`None`] 时直连。
pub fn ping_dns_with_proxy(
    target: &str,
    proxy: Option<&str>,
    timeout: Duration,
) -> io::Result<Duration> {
    let addr = resolve_target(target)?;
    let proxy = match proxy {
        None => None,
        Some(p) => Some(resolve_proxy(p)?),
    };
    ping_once(addr, proxy, timeout)
}

/// 多次 ping 并返回统计结果。
///
/// 仅在地址（或代理地址）解析失败时整体返回错误；每次采样本身的成功/失败
/// 都原样保留在 [`PingStat`] 中，不中断后续采样（贴近 `ping` 命令行为）。
///
/// - `target`: DNS 服务器地址
/// - `use_proxy`: 是否经 SOCKS5 代理转发
/// - `timeout`: 单次连接超时
/// - `count`: 采样次数（`0` 返回空统计）
pub fn ping_dns_multi(
    target: &str,
    proxy: Option<&str>,
    timeout: Duration,
    count: usize,
) -> io::Result<PingStat> {
    let addr = resolve_target(target)?;
    let proxy = match proxy {
        None => None,
        Some(p) => Some(resolve_proxy(p)?),
    };

    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        samples.push(ping_once(addr, proxy, timeout));
    }
    Ok(PingStat::from_samples(samples))
}

/// 单次握手测延迟的内部核心（地址与代理均已解析）。
///
/// 抽出此函数是为了让单次与多次两个公开入口，以及 `quality` 模块
/// 共享同一份握手逻辑（DRY）。
pub(crate) fn ping_once(
    addr: SocketAddr,
    proxy: Option<SocketAddr>,
    timeout: Duration,
) -> io::Result<Duration> {
    let start = Instant::now();
    let _stream = match proxy {
        None => TcpStream::connect_timeout(&addr, timeout)?,
        Some(proxy) => connect_socks5(proxy, addr, timeout)?,
    };
    // _stream 在此 drop：仅需完成握手以测延迟，不发送任何 DNS 业务数据。
    Ok(start.elapsed())
}

/// 计算一组（可能含失败的）延迟采样的平均值。
///
/// 成功项纳入平均，失败项忽略；全部失败或为空时返回 [`None`]。
/// 抽出为 `pub(crate)` 以供 `ping` 与 `quality` 两个模块共享统计逻辑（DRY）。
pub(crate) fn average_latency<'a, I>(durations: I) -> Option<Duration>
where
    I: IntoIterator<Item = Option<&'a Duration>>,
{
    let mut sum_ns: u128 = 0;
    let mut count: u128 = 0;
    for d in durations {
        if let Some(dur) = d {
            sum_ns += dur.as_nanos();
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    Some(Duration::from_nanos((sum_ns / count) as u64))
}

/// 多次 ping 的统计结果，保留每一次的原始结果（成功或错误）。
///
/// 所有统计量（平均/最小/最大/丢包率）均从成功样本计算；全部失败时
/// 延迟类统计返回 [`None`]，丢包率为 `1.0`。
///
/// 注意：因 [`io::Error`] 未实现 `Clone`，本类型不实现 `Clone`。
#[derive(Debug)]
pub struct PingStat {
    samples: Vec<io::Result<Duration>>,
}

impl PingStat {
    /// 由原始采样结果构造统计。
    pub fn from_samples(samples: Vec<io::Result<Duration>>) -> Self {
        Self { samples }
    }

    /// 原始采样序列（成功与错误均原样保留）。
    pub fn samples(&self) -> &[io::Result<Duration>] {
        &self.samples
    }

    /// 总采样次数。
    pub fn total_count(&self) -> usize {
        self.samples.len()
    }

    /// 成功次数。
    pub fn success_count(&self) -> usize {
        self.samples.iter().filter(|r| r.is_ok()).count()
    }

    /// 失败次数。
    pub fn fail_count(&self) -> usize {
        self.samples.iter().filter(|r| r.is_err()).count()
    }

    /// 成功样本的平均延迟；无成功样本时返回 [`None`]。
    pub fn avg_latency(&self) -> Option<Duration> {
        average_latency(self.samples.iter().map(|r| r.as_ref().ok()))
    }

    /// 成功样本的最小延迟；无成功样本时返回 [`None`]。
    pub fn min_latency(&self) -> Option<Duration> {
        self.samples
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .min()
            .copied()
    }

    /// 成功样本的最大延迟；无成功样本时返回 [`None`]。
    pub fn max_latency(&self) -> Option<Duration> {
        self.samples
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .max()
            .copied()
    }

    /// 丢包率，范围 `[0.0, 1.0]`；无样本时为 `0.0`。
    pub fn loss_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.fail_count() as f64 / self.total_count() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn ping_open_local_port_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = format!("127.0.0.1:{}", port);

        let latency = ping_dns(&target, false, Duration::from_secs(2)).unwrap();
        assert!(latency.as_nanos() > 0, "latency should be positive");
        drop(listener);
    }

    #[test]
    fn ping_closed_port_returns_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = format!("127.0.0.1:{}", port);
        let result = ping_dns(&target, false, Duration::from_millis(500));
        assert!(result.is_err(), "connecting to a closed port should fail");
    }

    #[test]
    fn ping_ipv6_loopback_succeeds() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = format!("[::1]:{}", port);

        let latency = ping_dns(&target, false, Duration::from_secs(2)).unwrap();
        assert!(latency.as_nanos() > 0);
        drop(listener);
    }

    #[test]
    fn ping_through_mock_proxy_succeeds() {
        use std::io::{Read, Write};
        use std::thread;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let proxy_handle = thread::spawn(move || {
            let (mut conn, _) = proxy_listener.accept().unwrap();
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
            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });

        let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = target_listener.local_addr().unwrap().port();

        let proxy = format!("127.0.0.1:{}", proxy_port);
        let target = format!("127.0.0.1:{}", target_port);
        let latency = ping_dns_with_proxy(&target, Some(&proxy), Duration::from_secs(2)).unwrap();
        assert!(latency.as_nanos() > 0);
        proxy_handle.join().unwrap();
    }

    /// 多次 ping 本地监听端口应全部成功，统计正确。
    #[test]
    fn multi_ping_local_all_succeed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = format!("127.0.0.1:{}", port);

        let stat = ping_dns_multi(&target, None, Duration::from_secs(2), 5).unwrap();
        assert_eq!(stat.total_count(), 5);
        assert_eq!(stat.success_count(), 5);
        assert_eq!(stat.fail_count(), 0);
        assert_eq!(stat.loss_rate(), 0.0);
        assert!(stat.avg_latency().is_some());
        assert!(stat.min_latency() <= stat.max_latency());
        // 平均应落在 [min, max] 区间内
        let (min, max, avg) = (
            stat.min_latency().unwrap(),
            stat.max_latency().unwrap(),
            stat.avg_latency().unwrap(),
        );
        assert!(avg >= min && avg <= max);
        drop(listener);
    }

    /// 采样次数为 0 时返回空统计，平均为 None。
    #[test]
    fn multi_ping_zero_count_is_empty() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = format!("127.0.0.1:{}", port);

        let stat = ping_dns_multi(&target, None, Duration::from_secs(2), 0).unwrap();
        assert_eq!(stat.total_count(), 0);
        assert_eq!(stat.avg_latency(), None);
        assert_eq!(stat.loss_rate(), 0.0);
        drop(listener);
    }

    /// 构造混合成功/失败的样本，验证统计计算（不依赖网络）。
    #[test]
    fn stat_mixed_samples_compute_correctly() {
        let samples = vec![
            Ok(Duration::from_millis(10)),
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "x")),
            Ok(Duration::from_millis(20)),
        ];
        let stat = PingStat::from_samples(samples);

        assert_eq!(stat.total_count(), 3);
        assert_eq!(stat.success_count(), 2);
        assert_eq!(stat.fail_count(), 1);
        assert_eq!(stat.avg_latency(), Some(Duration::from_millis(15)));
        assert_eq!(stat.min_latency(), Some(Duration::from_millis(10)));
        assert_eq!(stat.max_latency(), Some(Duration::from_millis(20)));
        assert!((stat.loss_rate() - 1.0 / 3.0).abs() < 1e-9);
    }

    /// 全部失败时延迟类统计为 None，丢包率为 1.0。
    #[test]
    fn stat_all_failed() {
        let samples = vec![
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "a")),
            Err(io::Error::new(io::ErrorKind::TimedOut, "b")),
        ];
        let stat = PingStat::from_samples(samples);

        assert_eq!(stat.success_count(), 0);
        assert_eq!(stat.avg_latency(), None);
        assert_eq!(stat.min_latency(), None);
        assert_eq!(stat.max_latency(), None);
        assert_eq!(stat.loss_rate(), 1.0);
    }
}
