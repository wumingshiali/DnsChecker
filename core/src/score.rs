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

/// 计算综合评分。
///
/// 公式: `score = (80 - dns_latency) * (100 - resolve_quality) * encryption * recommendation`
///
/// 当某个减法项为负（延迟超过基准）时，该项钳为 `5`：避免负数项导致分数
/// 符号异常或被错误地放大，以小正值表示「延迟超标但仍参与评分」。
///
/// # 参数
///
/// - `dns_latency`: DNS 服务器 ping 延迟（毫秒）。越小越好，80ms 为基准；超过 80ms 该项取 5。
/// - `resolve_quality`: 解析质量指标。**越小越好**（如解析后 ping 的平均延迟），100 为基准；超过 100 该项取 5。
///   注意：公式为 `100 - resolve_quality`，故传入「越小越好」的量（延迟/错误数等）才会得高分。
/// - `encryption`: 加密支持等级（[`Encryption`]），系数 0.5 / 0.75 / 1.0。
/// - `recommendation`: 推荐系数，推荐范围 `[0.5, 1.0]`。函数不做范围校验，由调用者保证。
///
/// # 返回
///
/// 最终分数，越大越好。
pub fn compute_score(
    dns_latency: f64,
    resolve_quality: f64,
    encryption: Encryption,
    recommendation: f64,
) -> f64 {
    let latency_term = nonneg_or((80.0 - dns_latency) / 2.0, 5.0);
    let quality_term = nonneg_or((100.0 - resolve_quality) / 1.5, 5.0);
    latency_term * quality_term * encryption.factor() * recommendation
}

/// 若 `value` 为负则替换为 `fallback`，否则保持原值。
fn nonneg_or(value: f64, fallback: f64) -> f64 {
    if value < 0.0 {
        fallback
    } else {
        value
    }
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
