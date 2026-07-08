"""
stats.py -- streaming statistics for TVLA.

TVLA (Test Vector Leakage Assessment) compares the timing distributions of two
input classes. If a Welch's two-sample t-test on their per-call cycle counts
produces |t| above a threshold (the community convention is 4.5), the two
distributions differ with overwhelming confidence -- i.e. execution time
depends on which class the input belonged to, which for a secret-dependent
class split means an exploitable timing leak.

Everything is computed online with Welford's algorithm so the live UI can show
the t-value converging without ever holding all samples in memory. Pure Python,
no numpy dependency required.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RunningStat:
    """Numerically stable online mean/variance (Welford)."""
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0          # sum of squares of deviations from the mean

    def push(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


@dataclass
class WelchTest:
    """Streaming Welch's t-test between two classes A and B."""
    a: RunningStat = field(default_factory=RunningStat)
    b: RunningStat = field(default_factory=RunningStat)

    def push_a(self, x: float) -> None:
        self.a.push(x)

    def push_b(self, x: float) -> None:
        self.b.push(x)

    @property
    def n(self) -> int:
        return self.a.n + self.b.n

    @property
    def t(self) -> float:
        """Welch's t statistic. 0.0 until both classes have >= 2 samples."""
        if self.a.n < 2 or self.b.n < 2:
            return 0.0
        va, vb = self.a.variance, self.b.variance
        na, nb = self.a.n, self.b.n
        denom = math.sqrt(va / na + vb / nb)
        if denom == 0.0:
            return 0.0
        return (self.a.mean - self.b.mean) / denom

    @property
    def dof(self) -> float:
        """Welch-Satterthwaite degrees of freedom."""
        va, vb = self.a.variance, self.b.variance
        na, nb = self.a.n, self.b.n
        if na < 2 or nb < 2:
            return 0.0
        sa, sb = va / na, vb / nb
        num = (sa + sb) ** 2
        den = (sa ** 2) / (na - 1) + (sb ** 2) / (nb - 1)
        return num / den if den else 0.0

    def confidence_interval(self, z: float = 1.96):
        """Approx CI for the mean difference (large-sample z, default 95%)."""
        va, vb = self.a.variance, self.b.variance
        na, nb = self.a.n, self.b.n
        if na < 2 or nb < 2:
            return (0.0, 0.0)
        se = math.sqrt(va / na + vb / nb)
        diff = self.a.mean - self.b.mean
        return (diff - z * se, diff + z * se)

    def snapshot(self) -> dict:
        lo, hi = self.confidence_interval()
        return {
            "t": self.t,
            "dof": self.dof,
            "n_a": self.a.n,
            "n_b": self.b.n,
            "mean_a": self.a.mean,
            "mean_b": self.b.mean,
            "var_a": self.a.variance,
            "var_b": self.b.variance,
            "diff": self.a.mean - self.b.mean,
            "ci95": (lo, hi),
        }


def crop_threshold(samples: List[int], percentile: float) -> float:
    """Return the value at `percentile` (0..100) for outlier cropping.

    dudect crops the upper tail before testing because a single preemption or
    interrupt can inject a huge outlier that inflates variance and hides real
    leaks. Callers typically drop samples above this threshold.
    """
    if not samples:
        return math.inf
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, int(len(ordered) * percentile / 100.0))
    return float(ordered[idx])


# Two-sided p-value approximation from t and dof, for reporting only. Uses the
# regularized incomplete beta function via a continued fraction (Numerical
# Recipes style) so we avoid a scipy dependency.
def _betacf(a: float, b: float, x: float) -> float:
    MAXIT, EPS, FPMIN = 200, 3e-12, 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < FPMIN:
        d = FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            break
    return h


def _betai(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    bt = math.exp(lbeta + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def two_sided_p(t: float, dof: float) -> float:
    """Two-sided p-value for a t statistic with `dof` degrees of freedom."""
    if dof <= 0:
        return 1.0
    return _betai(0.5 * dof, 0.5, dof / (dof + t * t))