//! 业务出口健康统计。
//!
//! supervisor 的恢复决策此前只有三个输入：探针成功、探针失败、刷新定时器。
//! **业务侧拨号的成败对它的影响是严格的零。** 现场因此出现过这样的组合：
//! 18 万次业务拨号超时、成功率 ~1%，而健康探针一路全绿、隧道始终不被重建——
//! 因为探针目标（`1.1.1.1:443` / `8.8.8.8:53` / `9.9.9.9:53`）全是 DNS/CDN
//! anycast，与「域名解析 → 第三方 Web 前端」这条真实业务路径根本不相交，
//! 而且 `min_successes = 2` 让 3 个目标里挂掉 1 个都不算故障。
//!
//! 光靠往 `health.targets` 里加目标是补不上的：那是 `Vec<SocketAddr>`，
//! 只能填 IP，覆盖不了「解析出来的域名 + 对方 Web 前端」。唯一能覆盖业务路径
//! 的观测点就是业务本身。
//!
//! 这里用一对无锁计数器把业务拨号成败喂给探针循环，让选择性出口故障
//! （探针目标可达、业务目标全挂）也能推动恢复阶梯。

use std::sync::atomic::{AtomicU64, Ordering};

/// 一个评估窗口内至少要有这么多次业务拨号，才允许据此判定出口降级。
///
/// 样本太少时失败率的方差极大：闲置代理上偶尔两三次拨到一个死地址，
/// 不该把整条隧道推去重建。
pub const MIN_SAMPLES: u64 = 20;

/// 窗口内失败率达到这个比例即视为出口降级。
///
/// 定得高（0.8）是刻意的：这个信号会推动重建/重注册/换身份这一整条阶梯，
/// 误判的代价远大于漏判。真正的选择性出口故障失败率接近 1.0（现场是 0.94），
/// 而正常业务的失败率通常在 0.05 以下，两者之间有很宽的安全带。
pub const FAIL_RATIO: f64 = 0.8;

/// 业务拨号的成败计数。每轮健康探针取走并清零。
#[derive(Debug, Default)]
pub struct EgressStats {
    ok: AtomicU64,
    failed: AtomicU64,
}

/// 一个评估窗口的快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressWindow {
    pub ok: u64,
    pub failed: u64,
}

impl EgressWindow {
    pub fn total(&self) -> u64 {
        self.ok.saturating_add(self.failed)
    }

    /// 样本是否足够多到可以下结论。
    pub fn has_quorum(&self) -> bool {
        self.total() >= MIN_SAMPLES
    }

    pub fn fail_ratio(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        self.failed as f64 / total as f64
    }

    /// 样本足够 **且** 失败率过线时才算降级。
    pub fn is_degraded(&self) -> bool {
        self.has_quorum() && self.fail_ratio() >= FAIL_RATIO
    }
}

impl EgressStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次业务拨号的最终结果（happy-eyeballs 全部候选耗尽后的结论）。
    pub fn record(&self, success: bool) {
        let counter = if success { &self.ok } else { &self.failed };
        // Relaxed 足够：这些计数之间没有顺序依赖，读侧只关心量级。
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 取走当前窗口并清零，供下一轮重新累计。
    pub fn take_window(&self) -> EgressWindow {
        EgressWindow {
            ok: self.ok.swap(0, Ordering::Relaxed),
            failed: self.failed.swap(0, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_needs_both_quorum_and_ratio() {
        // 失败率 100% 但样本不足 → 不下结论。
        let few = EgressWindow { ok: 0, failed: 5 };
        assert!(!few.has_quorum());
        assert!(!few.is_degraded(), "样本不足时不能判降级");

        // 样本足够但失败率不到线 → 正常。
        let noisy = EgressWindow { ok: 50, failed: 10 };
        assert!(noisy.has_quorum());
        assert!(!noisy.is_degraded());

        // 现场那次故障的量级：94% 失败。
        let outage = EgressWindow {
            ok: 12,
            failed: 188,
        };
        assert!(outage.is_degraded());
        assert!(outage.fail_ratio() > 0.9);

        // 正好卡在阈值上要算降级（>=，不是 >）。
        let exact = EgressWindow { ok: 20, failed: 80 };
        assert_eq!(exact.fail_ratio(), 0.8);
        assert!(exact.is_degraded());
    }

    #[test]
    fn take_window_resets_counters() {
        let stats = EgressStats::new();
        for _ in 0..3 {
            stats.record(true);
        }
        for _ in 0..7 {
            stats.record(false);
        }
        let first = stats.take_window();
        assert_eq!(first, EgressWindow { ok: 3, failed: 7 });

        // 取走之后必须归零，否则旧窗口会一直污染后续判断。
        let second = stats.take_window();
        assert_eq!(second, EgressWindow { ok: 0, failed: 0 });
        assert!(!second.has_quorum());
        assert_eq!(second.fail_ratio(), 0.0);
    }

    #[test]
    fn empty_window_is_not_degraded() {
        let idle = EgressWindow { ok: 0, failed: 0 };
        assert_eq!(idle.fail_ratio(), 0.0);
        assert!(!idle.is_degraded(), "空闲代理不能被判成故障");
    }
}
