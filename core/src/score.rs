//! DNS 服务器综合评分。
//!
//! 根据延迟、解析质量、加密支持与推荐系数计算最终分数。
//! 采用「平方反比衰减 + Smoothstep 连续权重」模型。

// ==================== 配置常量 ====================
/// DNS 延迟缩放因子（毫秒）：延迟等于此值时，得分衰减到 50 分
const DNS_SCALE: f64 = 50.0;
/// 解析延迟缩放因子（毫秒）：延迟等于此值时，得分衰减到 50 分
const RESOLVE_SCALE: f64 = 100.0;
/// DNS 延迟权重下限（当分数极低时）
const DNS_WEIGHT_MIN: f64 = 0.2;
/// DNS 延迟权重上限（当分数极高时）
const DNS_WEIGHT_MAX: f64 = 0.4;

/// DNS 加密支持等级，对应公式中的加密系数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// 无加密支持（如明文 DNS），系数 0.8。
    None,
    /// 部分加密支持，系数 0.9。
    Partial,
    /// 完全加密支持（如 DoT / DoH），系数 1.0。
    Full,
}

impl Encryption {
    /// 加密系数：`None=0.8`、`Partial=0.9`、`Full=1.0`。
    pub fn factor(self) -> f64 {
        match self {
            Encryption::None => 0.8,
            Encryption::Partial => 0.9,
            Encryption::Full => 1.0,
        }
    }
}

/// 计算综合评分。
///
/// # 参数
/// - `dns_latency`: DNS 服务器 ping 延迟（毫秒）。越小越好。
/// - `resolve_latency`: 解析后 ping 的平均延迟（毫秒）。越小越好。
/// - `encryption`: 加密支持等级（[`Encryption`]），系数 0.8 / 0.9 / 1.0。
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

    // 2. 平方反比衰减打分（比 Sigmoid 更快，同样平滑）
    let dns_score = inverse_square_score(dns_latency, DNS_SCALE);
    let resolve_score = inverse_square_score(resolve_latency, RESOLVE_SCALE);

    // 3. Smoothstep 连续动态权重（避免硬阈值跳变）
    let dns_weight = smooth_weight(dns_score, DNS_WEIGHT_MIN, DNS_WEIGHT_MAX);
    let resolve_weight = 1.0 - dns_weight;

    let base_score = dns_score * dns_weight + resolve_score * resolve_weight;

    // 4. 全局系数（加密适当扣分，无加密扣 20%）
    let final_score = base_score * encryption.factor() * recommendation;

    // 5. 兜底
    if final_score.is_finite() {
        final_score.max(0.0)
    } else {
        0.0
    }
}

/// 平方反比衰减：`100 / (1 + (latency / k)²)`
/// 比 Sigmoid 计算更快，且全程平滑无拐点
fn inverse_square_score(latency: f64, k: f64) -> f64 {
    let x = latency / k;
    100.0 / (1.0 + x * x)
}

/// Smoothstep 连续权重：分数越低权重越小，分数越高权重越大
/// 使用 smoothstep 函数平滑过渡，避免硬阈值跳变
fn smooth_weight(score: f64, min_weight: f64, max_weight: f64) -> f64 {
    let t = (score / 100.0).clamp(0.0, 1.0);
    let smooth = t * t * (3.0 - 2.0 * t); // smoothstep
    min_weight + smooth * (max_weight - min_weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_factors() {
        assert_eq!(Encryption::None.factor(), 0.8);
        assert_eq!(Encryption::Partial.factor(), 0.9);
        assert_eq!(Encryption::Full.factor(), 1.0);
    }

    #[test]
    fn score_excellent_latency_near_full_score() {
        // 延迟极低，平方反比输出接近 100
        let s = compute_score(10.0, 30.0, Encryption::Full, 1.0);
        assert!(s > 95.0, "got {}", s);
    }

    #[test]
    fn score_high_latency_decay() {
        // 延迟较高，平方反比输出显著下降
        let s = compute_score(150.0, 250.0, Encryption::Full, 1.0);
        assert!(s < 30.0, "got {}", s);
        assert!(s > 0.0);
    }

    #[test]
    fn score_none_encryption_moderate_penalty() {
        let full = compute_score(50.0, 100.0, Encryption::Full, 1.0);
        let none = compute_score(50.0, 100.0, Encryption::None, 1.0);
        // 无加密扣 20%，而不是之前的 50%
        assert!((none - full * 0.8).abs() < 1e-6, "none={}, full={}", none, full);
    }

    #[test]
    fn score_partial_encryption_slight_penalty() {
        let full = compute_score(50.0, 100.0, Encryption::Full, 1.0);
        let partial = compute_score(50.0, 100.0, Encryption::Partial, 1.0);
        // 部分加密扣 10%
        assert!((partial - full * 0.9).abs() < 1e-6);
    }

    #[test]
    fn score_smooth_weight_no_jump() {
        // 分数在阈值附近不应有权重跳变
        let s1 = compute_score(49.0, 100.0, Encryption::Full, 1.0);
        let s2 = compute_score(51.0, 100.0, Encryption::Full, 1.0);
        // 两者分数应该接近，没有突变
        assert!((s1 - s2).abs() < 5.0, "s1={}, s2={}", s1, s2);
    }

    #[test]
    fn score_recommendation_scales_linearly() {
        let base = compute_score(50.0, 100.0, Encryption::Full, 1.0);
        let half = compute_score(50.0, 100.0, Encryption::Full, 0.5);
        assert!((half - base * 0.5).abs() < 1e-6);
    }

    #[test]
    fn score_extreme_latency_clamped_to_zero() {
        // 延迟极高，平方反比输出趋近于 0
        let s = compute_score(10000.0, 10000.0, Encryption::Full, 1.0);
        assert!(s < 5.0, "got {}", s);
    }
}
