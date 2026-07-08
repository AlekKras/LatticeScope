//! The statistical core of the leakage assessment.
//!
//! TVLA (Goodwill–Jun–Jaffe–Rohatgi, 2011) reduces "does this code leak in the
//! timing channel?" to a two-sample **Welch t-test** between a *fixed* input
//! class (A) and a *random* input class (B). If their cycle-count distributions
//! are distinguishable, the timing is input-dependent.
//!
//! ## The threshold, honestly
//!
//! The conventional decision line is |t| > 4.5. For a **single** Welch test at
//! TVLA sample sizes that corresponds to a two-sided false-positive probability
//! on the order of 1e-5. We keep that interpretation for the *raw* t, which is
//! computed over the whole stream and reported as the primary statistic.
//!
//! Real measurements also have a heavy upper tail (preemptions, interrupts,
//! migrations) that can both *manufacture* a spurious difference and *mask* a
//! real one. Following dudect (Reparaz–Balasch–Gierlichs, 2017) we therefore
//! also compute the t-test after discarding the extreme upper tail, at a
//! **small fixed set** of crops, and report the largest resulting |t| as a
//! `tail_robust_t`.
//!
//! Two deliberate choices distinguish this from a naive "max over many crops":
//!
//!   * The crop set is tiny (3 nested crops), so the multiple-comparison
//!     inflation of the false-positive rate is negligible rather than material.
//!   * We do **not** claim the clean 1e-5 calibration for `tail_robust_t`. It
//!     is a *sensitivity* figure: a leak that only surfaces after cropping is
//!     still a leak, but a near-threshold tail-robust value on a noisy host
//!     warrants re-running pinned and quiesced before you trust it.
//!
//! The confidence interval on the mean difference uses the large-sample normal
//! approximation (z), which is indistinguishable from Student's t at n ≫ 10^4.

use std::collections::VecDeque;

/// Canonical TVLA decision line.
pub const THRESHOLD: f64 = 4.5;

/// z for a two-sided 95% CI (large-sample normal approximation).
const Z95: f64 = 1.959_963_984_540_054;

/// Upper-tail crops for the tail-robust statistic: fraction of samples kept.
/// Small and nested on purpose (see module docs).
const CROPS: [f64; 3] = [1.0, 0.95, 0.90];

/// Welford's online mean/variance — O(1) per sample, flat memory.
#[derive(Clone, Default)]
pub struct Online {
    pub n: u64,
    pub mean: f64,
    m2: f64,
}

impl Online {
    pub fn new() -> Online {
        Online::default()
    }

    #[inline]
    pub fn push(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
    }

    /// Sample variance (n − 1 denominator). Zero until two samples.
    pub fn var(&self) -> f64 {
        if self.n > 1 {
            self.m2 / (self.n as f64 - 1.0)
        } else {
            0.0
        }
    }
}

/// Result of a Welch t-test between two classes.
#[derive(Clone, Debug)]
pub struct TResult {
    pub t: f64,
    pub dof: f64,
    pub mean_a: f64,
    pub mean_b: f64,
    pub var_a: f64,
    pub var_b: f64,
    pub n_a: u64,
    pub n_b: u64,
    // ponytail: only read from #[test] assertions, which release builds don't
    // compile — hence the dead_code warning outside `cargo test`.
    #[allow(dead_code)]
    pub diff: f64,
    #[allow(dead_code)]
    pub stderr: f64,
    pub ci_low: f64,
    pub ci_high: f64,
}

impl TResult {
    fn empty() -> TResult {
        TResult {
            t: 0.0,
            dof: 0.0,
            mean_a: 0.0,
            mean_b: 0.0,
            var_a: 0.0,
            var_b: 0.0,
            n_a: 0,
            n_b: 0,
            diff: 0.0,
            stderr: 0.0,
            ci_low: 0.0,
            ci_high: 0.0,
        }
    }

    #[allow(dead_code)]
    pub fn leaks(&self) -> bool {
        self.t.abs() > THRESHOLD
    }
}

/// Welch's unequal-variance t-test between two online accumulators.
pub fn welch(a: &Online, b: &Online) -> TResult {
    let (na, nb) = (a.n, b.n);
    let (va, vb) = (a.var(), b.var());
    if na < 2 || nb < 2 {
        let mut r = TResult::empty();
        r.mean_a = a.mean;
        r.mean_b = b.mean;
        r.var_a = va;
        r.var_b = vb;
        r.n_a = na;
        r.n_b = nb;
        return r;
    }

    let sa = va / na as f64; // = s_a^2 / n_a  (squared standard error, class A)
    let sb = vb / nb as f64;
    let se = (sa + sb).sqrt();
    let diff = a.mean - b.mean;
    let t = if se > 0.0 { diff / se } else { 0.0 };

    // Welch–Satterthwaite effective degrees of freedom.
    let denom = sa * sa / (na as f64 - 1.0) + sb * sb / (nb as f64 - 1.0);
    let dof = if denom > 0.0 { (sa + sb).powi(2) / denom } else { 0.0 };

    let ci = Z95 * se;
    TResult {
        t,
        dof,
        mean_a: a.mean,
        mean_b: b.mean,
        var_a: va,
        var_b: vb,
        n_a: na,
        n_b: nb,
        diff,
        stderr: se,
        ci_low: diff - ci,
        ci_high: diff + ci,
    }
}

/// Bounded, class-labelled **window** of the most recent samples, used only to
/// compute the tail-robust cropped statistic. (This is a recency window, not
/// reservoir sampling — the raw statistic above already covers the full stream
/// with flat memory.)
pub struct TailWindow {
    buf: VecDeque<(u8, f64)>, // (class, value); class 0 = fixed, 1 = random
    cap: usize,
}

impl TailWindow {
    pub fn new(capacity: usize) -> TailWindow {
        TailWindow { buf: VecDeque::with_capacity(capacity), cap: capacity }
    }

    #[inline]
    pub fn push(&mut self, class: u8, value: f64) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back((class, value));
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[allow(dead_code)]
    /// Visit each recent `(class, value)` sample (used to build the histogram).
    pub fn for_each<F: FnMut(u8, f64)>(&self, mut f: F) {
        for &(cls, v) in self.buf.iter() {
            f(cls, v);
        }
    }

    /// Evaluate Welch's t at each fixed crop and return the (result, kept-fraction)
    /// with the largest |t|. The cutoff is a single pooled percentile applied to
    /// *both* classes, so the comparison is never distorted by cropping the two
    /// classes at different thresholds.
    pub fn evaluate(&self) -> (TResult, f64) {
        if self.buf.len() < 8 {
            return (TResult::empty(), 1.0);
        }
        let mut sorted: Vec<f64> = self.buf.iter().map(|&(_, v)| v).collect();
        sorted.sort_unstable_by(|x, y| x.partial_cmp(y).unwrap());

        let mut best = TResult::empty();
        let mut best_frac = 1.0;
        let mut best_abs = -1.0;

        for &frac in CROPS.iter() {
            let cutoff = percentile(&sorted, frac);
            let mut a = Online::new();
            let mut b = Online::new();
            for &(cls, v) in self.buf.iter() {
                if v <= cutoff {
                    if cls == 0 {
                        a.push(v);
                    } else {
                        b.push(v);
                    }
                }
            }
            let res = welch(&a, &b);
            if res.t.abs() > best_abs {
                best_abs = res.t.abs();
                best = res;
                best_frac = frac;
            }
        }
        (best, best_frac)
    }
}

/// Value at `frac` of a pre-sorted slice (nearest-rank).
fn percentile(sorted: &[f64], frac: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if frac >= 1.0 {
        return sorted[sorted.len() - 1];
    }
    let idx = ((frac * (sorted.len() - 1) as f64) as usize).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welford_matches_naive() {
        let data = [10.0, 12.0, 23.0, 23.0, 16.0, 23.0, 21.0, 16.0];
        let mut o = Online::new();
        for &x in &data {
            o.push(x);
        }
        let mean = data.iter().sum::<f64>() / data.len() as f64;
        let var = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (data.len() as f64 - 1.0);
        assert!((o.mean - mean).abs() < 1e-9);
        assert!((o.var() - var).abs() < 1e-9);
    }

    #[test]
    fn identical_classes_do_not_leak() {
        let mut a = Online::new();
        let mut b = Online::new();
        for i in 0..10_000 {
            let x = (i % 100) as f64;
            a.push(x);
            b.push(x);
        }
        assert!(!welch(&a, &b).leaks());
    }

    #[test]
    fn separated_classes_leak() {
        let mut a = Online::new();
        let mut b = Online::new();
        for i in 0..10_000 {
            a.push((i % 100) as f64);
            b.push((i % 100) as f64 + 50.0);
        }
        let r = welch(&a, &b);
        assert!(r.leaks());
        assert!(r.diff < 0.0); // A - B
    }
}