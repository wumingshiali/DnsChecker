//! DNS 服务器综合评分。
//!
//! 根据延迟、解析质量、加密支持与推荐系数计算最终分数。
//! 公式: `score = (80 - dns_latency) * (100 - resolve_quality) * encryption * recommendation`

/// DNS 加密支持等级，对应公式中的加密系数（0.5 / 0.75 / 1.0）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// 无加密支持（如明文 DNS），系数 0.5。
    None,
    /// 部分加密支持，系数 0.75。
    Partial,
    /// 完全加密支持（如 DoT / DoH），系数 1.0。
    Full,
}

impl Encryption {
    /// 加密系数：`None=0.5`、`Partial=0.75`、`Full=1.0`。
    pub fn factor(self) -> f64 {
        match self {
            Encryption::None => 0.5,
            Encryption::Partial => 0.75,
            Encryption::Full => 1.0,
        }
    }
}

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

    // 2. 核心算法：反比例衰减模型
    // 公式: Score = Base / (1 + latency / k)
    // k 是半衰期常数。当 latency = k 时，得分衰减到 Base 的一半。
    
    // 假设基础分为 100，DNS延迟半衰期设为 50ms (即 50ms 时得 50分，100ms 时得 33分)
    let latency_score = 100.0 / (1.0 + dns_latency / 50.0);
    
    // 解析质量半衰期设为 80ms
    let quality_score = 100.0 / (1.0 + resolve_latency / 80.0);

    // 3. 加权融合 (改用加权平均或带底数的乘法，避免雪崩)
    // 这里采用几何平均的变体，或者简单的加权乘法，保证平滑
    let base_score = (latency_score * quality_score).sqrt(); // 几何平均，防止单项过高掩盖另一项的拉胯

    // 4. 乘以系数
    let final_score = base_score * encryption.factor() * recommendation;

    if final_score.is_finite() { final_score } else { 0.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_factors() {
        assert_eq!(Encryption::None.factor(), 0.5);
        assert_eq!(Encryption::Partial.factor(), 0.75);
        assert_eq!(Encryption::Full.factor(), 1.0);
    }

    /// (80-20)/2 * (100-30)/1.5 * 1.0 * 1.0 = 30 * (70/1.5) = 1400
    #[test]
    fn score_basic_full_encryption() {
        let s = compute_score(20.0, 30.0, Encryption::Full, 1.0);
        assert!((s - 1400.0).abs() < 1e-6, "got {}", s);
    }

    /// 无加密应使分数减半：1400 -> 700
    #[test]
    fn score_none_encryption_halves() {
        let full = compute_score(20.0, 30.0, Encryption::Full, 1.0);
        let none = compute_score(20.0, 30.0, Encryption::None, 1.0);
        assert!((none - full * 0.5).abs() < 1e-6);
        assert!((none - 700.0).abs() < 1e-6);
    }

    /// 部分加密：1400 * 0.75 = 1050
    #[test]
    fn score_partial_encryption() {
        let s = compute_score(20.0, 30.0, Encryption::Partial, 1.0);
        assert!((s - 1050.0).abs() < 1e-6);
    }

    /// 推荐系数线性缩放：1.0 -> 1400, 0.5 -> 700
    #[test]
    fn score_recommendation_scales_linearly() {
        let base = compute_score(20.0, 30.0, Encryption::Full, 1.0);
        let half = compute_score(20.0, 30.0, Encryption::Full, 0.5);
        assert!((half - base * 0.5).abs() < 1e-6);
        assert!((half - 700.0).abs() < 1e-6);
    }

    /// 零延迟零质量得满分：80/2 * 100/1.5 = 40 * (100/1.5) = 8000/3
    #[test]
    fn score_zero_latency_and_quality() {
        let s = compute_score(0.0, 0.0, Encryption::Full, 1.0);
        assert!((s - 8000.0 / 3.0).abs() < 1e-6);
    }

    /// 延迟超过基准时该项钳为 5，分数仍为正。
    /// score = 5 * (100-30)/1.5 * 1 * 1 = 5 * (70/1.5) = 700/3
    #[test]
    fn score_latency_exceeds_baseline_clamped_to_5() {
        let s = compute_score(100.0, 30.0, Encryption::Full, 1.0);
        assert!((s - 700.0 / 3.0).abs() < 1e-6, "got {}", s);
        assert!(s > 0.0);
    }

    /// 解析质量超过基准时该项钳为 5。
    /// score = (80-20)/2 * 5 * 1 * 1 = 30 * 5 = 150
    #[test]
    fn score_quality_exceeds_baseline_clamped_to_5() {
        let s = compute_score(20.0, 120.0, Encryption::Full, 1.0);
        assert!((s - 150.0).abs() < 1e-6, "got {}", s);
    }

    /// 两个减法项都为负时都钳为 5。
    /// score = 5 * 5 * 1 * 1 = 25
    #[test]
    fn score_both_terms_clamped_to_5() {
        let s = compute_score(100.0, 120.0, Encryption::Full, 1.0);
        assert!((s - 25.0).abs() < 1e-6, "got {}", s);
    }
}
