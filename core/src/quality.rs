//! 解析质量检测：用指定 DNS 服务器解析一组域名，对每个解析到的 IP
//! 执行 ping，汇总所有延迟并返回平均。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::addr::resolve_proxy;
use crate::dns::resolve as dns_resolve;
use crate::ping::{average_latency, ping_once};

/// 默认解析质量检测域名集。
pub const QUALITY_DOMAINS: &[&str] = &[
    "qq.com",
    "alibaba.com",
    "dev.meali.top",
    "edgeone.ai",
    "microsoft.com",
    "apple.com",
];

/// 单个 (域名, IP) 的 ping 采样结果。
#[derive(Debug)]
pub struct QualitySample {
    pub domain: String,
    pub ip: IpAddr,
    pub latency: io::Result<Duration>,
}

/// 解析失败的域名及其错误。
#[derive(Debug)]
pub struct ResolveFailure {
    pub domain: String,
    pub error: io::Error,
}

/// 解析质量检测报告。
#[derive(Debug)]
pub struct QualityReport {
    /// 每个 (域名, IP) 的 ping 结果（成功与错误均原样保留）。
    pub samples: Vec<QualitySample>,
    /// 解析失败的域名及其错误。
    pub failures: Vec<ResolveFailure>,
}

impl QualityReport {
    /// 所有成功 ping 延迟的平均；无成功样本时返回 [`None`]。
    pub fn avg_latency(&self) -> Option<Duration> {
        average_latency(self.samples.iter().map(|s| s.latency.as_ref().ok()))
    }

    /// ping 采样总数。
    pub fn total_count(&self) -> usize {
        self.samples.len()
    }

    /// ping 成功次数。
    pub fn success_count(&self) -> usize {
        self.samples.iter().filter(|s| s.latency.is_ok()).count()
    }

    /// ping 失败次数。
    pub fn fail_count(&self) -> usize {
        self.samples.iter().filter(|s| s.latency.is_err()).count()
    }

    /// 解析失败次数（与 ping 失败独立计数）。
    pub fn resolve_failure_count(&self) -> usize {
        self.failures.len()
    }
}

/// 用指定 DNS 服务器解析 [`QUALITY_DOMAINS`]，ping 每个 IP，返回报告。
///
/// `timeout` 同时用于 DNS 查询与单次 ping。仅在代理地址解析失败时返回错误；
/// 单个域名的解析失败与单个 IP 的 ping 失败均记录在报告中，不中断整体流程。
///
/// `proxy` 为 `Some(addr)`（如 `127.0.0.1:1080`）时经 SOCKS5 代理；
/// `doh` 为 `Some(url)` 时使用 DNS over HTTPS 解析（直连，忽略 `dns_server`
/// 与 `proxy`）；`None` 时走明文 DNS over TCP。
pub fn check_resolve_quality(
    dns_server: &str,
    proxy: Option<&str>,
    timeout: Duration,
    doh: Option<&str>,
) -> io::Result<QualityReport> {
    check_resolve_quality_for(dns_server, QUALITY_DOMAINS, proxy, timeout, timeout, doh)
}

/// 自定义域名集与独立超时的版本。
///
/// - `query_timeout`: DNS 查询超时
/// - `ping_timeout`: 单次 ping 超时
pub fn check_resolve_quality_for(
    dns_server: &str,
    domains: &[&str],
    proxy: Option<&str>,
    query_timeout: Duration,
    ping_timeout: Duration,
    doh: Option<&str>,
) -> io::Result<QualityReport> {
    // 代理地址只解析一次，循环内复用（ping 用 SocketAddr，DNS 查询用原 &str）
    let proxy_addr = match proxy {
        None => None,
        Some(p) => Some(resolve_proxy(p)?),
    };

    let mut samples = Vec::new();
    let mut failures = Vec::new();

    for domain in domains {
        match dns_resolve(dns_server, domain, query_timeout, proxy, doh) {
            Ok(ips) => {
                for ip in ips {
                    let addr = SocketAddr::new(ip, crate::DNS_PORT);
                    let latency = ping_once(addr, proxy_addr, ping_timeout);
                    samples.push(QualitySample {
                        domain: domain.to_string(),
                        ip,
                        latency,
                    });
                }
            }
            Err(error) => {
                failures.push(ResolveFailure {
                    domain: domain.to_string(),
                    error,
                });
            }
        }
    }

    Ok(QualityReport { samples, failures })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn report_avg_of_successful_pings() {
        let report = QualityReport {
            samples: vec![
                QualitySample {
                    domain: "a.com".into(),
                    ip: "1.1.1.1".parse().unwrap(),
                    latency: Ok(Duration::from_millis(10)),
                },
                QualitySample {
                    domain: "a.com".into(),
                    ip: "1.1.1.2".parse().unwrap(),
                    latency: Ok(Duration::from_millis(20)),
                },
                QualitySample {
                    domain: "b.com".into(),
                    ip: "2.2.2.2".parse().unwrap(),
                    latency: Err(io::Error::new(io::ErrorKind::ConnectionRefused, "x")),
                },
            ],
            failures: vec![],
        };
        assert_eq!(report.total_count(), 3);
        assert_eq!(report.success_count(), 2);
        assert_eq!(report.fail_count(), 1);
        assert_eq!(report.resolve_failure_count(), 0);
        assert_eq!(report.avg_latency(), Some(Duration::from_millis(15)));
    }

    #[test]
    fn report_avg_none_when_all_pings_fail() {
        let report = QualityReport {
            samples: vec![QualitySample {
                domain: "a.com".into(),
                ip: "1.1.1.1".parse::<IpAddr>().unwrap(),
                latency: Err(io::Error::new(io::ErrorKind::TimedOut, "t")),
            }],
            failures: vec![ResolveFailure {
                domain: "c.com".into(),
                error: io::Error::new(io::ErrorKind::AddrNotAvailable, "nx"),
            }],
        };
        assert_eq!(report.avg_latency(), None);
        assert_eq!(report.resolve_failure_count(), 1);
    }

    /// 端到端联网测试：默认需联网到 8.8.8.8，用 `--ignored` 手动运行。
    #[test]
    #[ignore = "requires network access to 8.8.8.8"]
    fn quality_check_real_dns() {
        let report = check_resolve_quality("8.8.8.8", None, Duration::from_secs(4), None).unwrap();
        assert!(report.samples.len() + report.failures.len() > 0);
    }

    /// 诊断国外 DNS 的 DoH->TCP 回退是否生效（单域名 resolve）。
    #[test]
    #[ignore = "diagnostic: DoH fallback to TCP"]
    fn diag_foreign_dns() {
        use crate::dns::resolve;
        let cases = [
            ("1.1.1.1", "https://cloudflare-dns.com/dns-query"),
            ("8.8.8.8", "https://dns.google/dns-query"),
            ("9.9.9.9", "https://dns.quad9.net/dns-query"),
        ];
        for (addr, doh) in cases {
            // DoH 失败应回退到该 DNS 的 TCP 53 解析
            let res = resolve(addr, "qq.com", Duration::from_secs(8), None, Some(doh));
            eprintln!(
                "[{}] resolve qq.com -> {:?}",
                addr,
                res.as_ref().map(|v| v.len())
            );
        }
    }
}
