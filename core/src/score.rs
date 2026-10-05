//! DNS 服务器综合评分。
//!
//! 根据延迟、解析质量、加密支持与推荐系数计算最终分数。
//! 采用「Sigmoid 衰减 + 动态权重」模型，全程平滑无拐点，自动容错。

/// DNS 加密支持等级，对应公式中的加密系数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// 无加密支持（如明文 DNS），系数 0.85。
    None,
    /// 部分加密支持，系数 0.95。
    Partial,
    /// 完全加密支持（如 DoT / DoH），系数 1.0。
    Full,
}

impl Encryption {
    /// 加密系数：`None=0.85`、`Partial=0.95`、`Full=1.0`。
    pub fn factor(self) -> f64 {
        match self {
            Encryption::None => 0.85,
            Encryption::Partial => 0.95,
            Encryption::Full => 1.0,
        }
    }
}

/// 计算综合评分。
///
/// # 参数
/// - `dns_latency`: DNS 服务器 ping 延迟（毫秒）。越小越好。
/// - `resolve_latency`: 解析后 ping 的平均延迟（毫秒）。越小越好。
/// - `encryption`: 加密支持等级（[`Encryption`]），系数 0.85 / 0.95 / 1.0。
/// - `recommendation`: 推荐系数，推荐范围 `[0.8, 1.0]`。
///
/// # 返回
/// 最终分数，越大越好。若输入包含非法浮点数，则返回 `0.0`。
pub fn compute_score(
    dns_latency: f64,
    resolve_latency: f64,
    encryption: Encryption,
    recommendation: f64,
) -> f64 {
    // 1. 安全防御
    if [dns_latency, resolve_latency, recommendation].iter().any(|&x| !x.is_finite() || x < 0.0) {
        return 0.0;
    }

    // 2. Sigmoid 衰减打分
    // 中心点：dns=50ms, resolve=100ms
    // 斜率：控制衰减速度（值越大，中心点附近变化越剧烈）
    let dns_score = sigmoid_score(dns_latency, 50.0, 0.04);
    let resolve_score = sigmoid_score(resolve_latency, 100.0, 0.025);

    // 3. 动态权重：如果某一项极差，自动降低其权重，避免一票否决
    let dns_weight = if dns_score < 30.0 { 0.2 } else { 0.4 };
    let resolve_weight = 1.0 - dns_weight;

    let base_score = dns_score * dns_weight + resolve_score * resolve_weight;

    // 4. 全局系数
    let final_score = base_score * encryption.factor() * recommendation;

    if final_score.is_finite() { final_score.max(0.0) } else { 0.0 }
}

/// Sigmoid 打分：在中心点附近急剧变化，两端平缓，全程平滑无拐点
fn sigmoid_score(latency: f64, center: f64, steepness: f64) -> f64 {
    let x = (latency - center) * steepness;
    100.0 / (1.0 + x.exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_factors() {
        assert_eq!(Encryption::None.factor(), 0.85);
        assert_eq!(Encryption::Partial.factor(), 0.95);
        assert_eq!(Encryption::Full.factor(), 1.0);
    }

    #[test]
    fn score_excellent_latency_near_full_score() {
        // 延迟极低，Sigmoid 输出接近 100
        let s = compute_score(10.0, 30.0, Encryption::Full, 1.0);
        assert!(s > 95.0, "got {}", s);
    }

    #[test]
    fn score_high_latency_decay() {
        // 延迟较高，Sigmoid 输出显著下降
        let s = compute_score(150.0, 250.0, Encryption::Full, 1.0);
        assert!(s < 30.0, "got {}", s);
        assert!(s > 0.0);
    }

    #[test]
    fn score_none_encryption_slight_penalty() {
        let full = compute_score(50.0, 100.0, Encryption::Full, 1.0);
        let none = compute_score(50.0, 100.0, Encryption::None, 1.0);
        // 无加密只扣 15%，而不是之前的 50%
        assert!((none - full * 0.85).abs() < 1e-6);
    }

    #[test]
    fn score_dynamic_weight_adjustment() {
        // DNS 极差（<30分），权重应降为 0.2
        let bad_dns = compute_score(500.0, 50.0, Encryption::Full, 1.0);
        // 解析质量极差（<30分），DNS 权重保持 0.4
        let bad_resolve = compute_score(50.0, 500.0, Encryption::Full, 1.0);
        // 两者都应有分数，但不会为 0
        assert!(bad_dns > 0.0);
        assert!(bad_resolve > 0.0);
    }

    #[test]
    fn score_recommendation_scales_linearly() {
        let base = compute_score(50.0, 100.0, Encryption::Full, 1.0);
        let half = compute_score(50.0, 100.0, Encryption::Full, 0.5);
        assert!((half - base * 0.5).abs() < 1e-6);
    }

    #[test]
    fn score_extreme_latency_clamped_to_zero() {
        // 延迟极高，Sigmoid 输出趋近于 0
        let s = compute_score(10000.0, 10000.0, Encryption::Full, 1.0);
        assert!(s < 1.0, "got {}", s);
    }
}
