"""
tvla.py -- Test Vector Leakage Assessment for ML-KEM decapsulation.

Method
------
We split inputs into two classes and time decapsulation of each under
identical conditions, interleaving classes within every batch so that slow
drift (thermal, frequency) affects both equally and cancels in the difference.
A streaming Welch's t-test tracks the divergence. The calibrated verdict is the
*full-stream* |t| at the final n crossing 4.5 (a single-look ~1e-5 gate); the
running max of |t| over the trajectory is reported only as an uncalibrated
sensitivity figure, since gating on it would be optional-stopping and inflate
the false-positive rate.

Class definitions (KEM decapsulation)
-------------------------------------
* fixed-invalid (default) -- Class A is a *fixed* ciphertext deliberately
  corrupted so the FO re-encryption check fails and the implicit-rejection
  branch is taken; Class B is a stream of fresh valid ciphertexts from the
  target's own encapsulation. This directly probes whether the rejection path
  is constant-time relative to the success path -- the KyberSlash / implicit-
  rejection family of leaks.
* fixed-random -- Class A is one fixed valid ciphertext, Class B many random
  valid ciphertexts. A generic first-order test for any input dependence.

Measurement hygiene
--------------------
The tight timing loop runs in C (cshim.ct_time_dec) to keep CPython jitter out
of the signal. We pin to a single core and attempt to raise scheduling
priority. For publishable numbers also disable turbo and set the performance
governor (see README).
"""

from __future__ import annotations

import ctypes
import os
import secrets
from dataclasses import dataclass
from typing import Iterator, List, Optional

from . import build_shim
from .stats import WelchTest, crop_threshold, two_sided_p
from .target import KemTarget, SignTarget


DEFAULT_THRESHOLD = 4.5


@dataclass
class TvlaConfig:
    mode: str = "fixed-invalid"     # or "fixed-random"
    max_iterations: int = 2_000_000
    batch: int = 4096               # measurements per shim call
    warmup: int = 64                # untimed calls before each batch
    threshold: float = DEFAULT_THRESHOLD
    crop_percentile: float = 99.5   # drop samples above this (interrupt spikes)
    crop_enabled: bool = True
    core: Optional[int] = None      # pin core; None -> highest available
    rerandomize_invalid: bool = False
    stop_on_leak: bool = False      # halt as soon as |t| crosses the threshold
    seed: Optional[int] = None


@dataclass
class TvlaSnapshot:
    iterations: int
    t: float
    max_abs_t: float
    dof: float
    p_value: float
    mean_a: float
    mean_b: float
    diff: float
    ci95: tuple
    n_a: int
    n_b: int
    exec_per_s: float
    leaking: bool
    pinned_core: Optional[int]


def pin_and_prioritize(core: Optional[int]) -> Optional[int]:
    """Pin the current thread to a core and try to raise priority.

    Returns the core actually pinned to, or None if unsupported. Failures are
    non-fatal -- the tool still runs, just with more measurement noise.
    """
    chosen = None
    try:
        avail = sorted(os.sched_getaffinity(0))
        chosen = core if core is not None else avail[-1]
        os.sched_setaffinity(0, {chosen})
    except (AttributeError, OSError):
        chosen = None
    # Best-effort priority bump. SCHED_FIFO needs privileges; niceness usually
    # does not below the default. We try the strongest that works silently.
    try:
        param = os.sched_param(os.sched_get_priority_max(os.SCHED_FIFO))
        os.sched_setscheduler(0, os.SCHED_FIFO, param)
    except (AttributeError, OSError, PermissionError):
        try:
            os.setpriority(os.PRIO_PROCESS, 0, -20)
        except (OSError, PermissionError):
            pass
    return chosen


class _StreamingLeakTest:
    """Shared streaming Welch's-t driver for the interleaved-class timing tests.

    Subclasses build their fixed material in __init__ (after super().__init__)
    and implement `_measure_batch(n) -> (labels, cycles)`: an interleaved
    class-A / class-B schedule timed in C. Everything below -- outlier
    cropping, the streaming Welch update, snapshot emission -- is identical for
    KEM decapsulation and ML-DSA verification, so it lives here once.
    """

    def __init__(self, cfg: TvlaConfig):
        self.cfg = cfg
        self.lib = build_shim.load()
        self.rng = secrets.SystemRandom() if cfg.seed is None else _SeededRng(cfg.seed)
        self.welch = WelchTest()
        self._crop_thr = float("inf")
        self._crop_samples: List[int] = []

    def _measure_batch(self, n: int):
        raise NotImplementedError

    def _maybe_update_crop(self, cycles) -> None:
        """Refresh the crop threshold from a fresh window every 4096 samples,
        for the life of the run (not just once) -- a one-time baseline would
        go stale if thermal throttling or load shifts the noise floor mid-run."""
        if not self.cfg.crop_enabled:
            return
        self._crop_samples.extend(int(c) for c in cycles)
        if len(self._crop_samples) >= 4096:
            self._crop_thr = crop_threshold(self._crop_samples, self.cfg.crop_percentile)
            self._crop_samples = []

    # -- main streaming loop --------------------------------------------
    def run(self) -> Iterator[TvlaSnapshot]:
        import time
        pinned_core = pin_and_prioritize(self.cfg.core)
        max_abs_t = 0.0
        done = 0
        start = time.perf_counter()

        while done < self.cfg.max_iterations:
            n = min(self.cfg.batch, self.cfg.max_iterations - done)
            labels, cycles = self._measure_batch(n)
            self._maybe_update_crop(cycles)

            for i in range(n):
                c = int(cycles[i])
                if self.cfg.crop_enabled and c > self._crop_thr:
                    continue
                if labels[i]:
                    self.welch.push_a(c)
                else:
                    self.welch.push_b(c)

            done += n
            t = self.welch.t
            max_abs_t = max(max_abs_t, abs(t))
            elapsed = max(time.perf_counter() - start, 1e-9)
            snap = self.welch.snapshot()
            yield TvlaSnapshot(
                iterations=done,
                t=t,
                max_abs_t=max_abs_t,
                dof=snap["dof"],
                p_value=two_sided_p(t, snap["dof"]),
                mean_a=snap["mean_a"],
                mean_b=snap["mean_b"],
                diff=snap["diff"],
                ci95=snap["ci95"],
                n_a=snap["n_a"],
                n_b=snap["n_b"],
                exec_per_s=done / elapsed,
                # Calibrated verdict: the full-stream Welch t at the current n,
                # NOT the running max. |t| > 4.5 is a *single-look* ~1e-5 gate;
                # re-checking it every batch and flagging on the trajectory's
                # peak is optional-stopping (peeking), which drives the
                # false-positive rate far above 1e-5 on a genuinely constant-
                # time target -- the cumulative t is ~N(0,1) at every n, so its
                # supremum over a long run crosses 4.5 routinely under H0.
                # max_abs_t is still reported (below) as an uncalibrated
                # sensitivity figure: a peak that later settles is a hint to
                # re-run pinned/quiesced, not a leak verdict.
                leaking=abs(t) > self.cfg.threshold,
                pinned_core=pinned_core,
            )


class KemLeakageTest(_StreamingLeakTest):
    def __init__(self, target: KemTarget, cfg: TvlaConfig):
        super().__init__(cfg)
        self.t = target

        # Fixed key material and the fixed Class-A ciphertext, generated once
        # from the target itself.
        self.pk, self.sk = target.keypair()
        valid_ct, _ = target.enc(self.pk)
        self.fixed_valid_ct = valid_ct
        self.fixed_invalid_ct = self._corrupt(valid_ct)

        self._sk_buf = (ctypes.c_uint8 * self.t.sk_len)(*self.sk)

    # -- class material --------------------------------------------------
    def _corrupt(self, ct: bytes) -> bytes:
        """Flip a byte in the v-region so re-encryption fails -> rejection."""
        b = bytearray(ct)
        idx = len(b) - 1                      # last byte lives in v
        b[idx] ^= 0xFF
        return bytes(b)

    def _class_a_ct(self) -> bytes:
        if self.cfg.mode == "fixed-random":
            return self.fixed_valid_ct
        if self.cfg.rerandomize_invalid:
            v, _ = self.t.enc(self.pk)
            return self._corrupt(v)
        return self.fixed_invalid_ct

    def _class_b_ct(self) -> bytes:
        ct, _ = self.t.enc(self.pk)           # fresh valid ciphertext
        return ct

    # -- one measured batch ---------------------------------------------
    def _measure_batch(self, n: int):
        """Build an interleaved A/B schedule, time it in C, return (labels, cycles)."""
        ct_len = self.t.ct_len
        labels = bytearray(n)
        blob = bytearray(n * ct_len)
        for i in range(n):
            is_a = (self.rng.random() < 0.5)
            labels[i] = 1 if is_a else 0
            ct = self._class_a_ct() if is_a else self._class_b_ct()
            blob[i * ct_len:(i + 1) * ct_len] = ct

        cts = (ctypes.c_uint8 * len(blob)).from_buffer(blob)
        out = (ctypes.c_uint64 * n)()
        rc = self.lib.ct_time_dec(
            ctypes.c_void_p(self.t.dec_addr),
            self._sk_buf, cts,
            ctypes.c_size_t(ct_len),
            ctypes.c_size_t(self.t.ss_len),
            ctypes.c_size_t(n),
            ctypes.c_uint(self.cfg.warmup),
            out,
        )
        if rc != 0:
            raise RuntimeError("ct_time_dec failed (bad argument to shim)")
        return labels, out


class SignLeakageTest(_StreamingLeakTest):
    """TVLA on ML-DSA signature *verification*.

    Class definitions (parallel to the KEM decapsulation ones):
    * fixed-invalid (default) -- Class A is a fixed *corrupted* signature, so
      verify takes the reject path (where rejection-sampling / hint-decode
      early aborts leak in real ML-DSA); Class B is fresh *valid* signatures
      minted by the target's own signer. Probes reject-vs-accept constant-time.
    * fixed-random -- Class A one fixed valid signature, Class B fresh valid
      ones. A generic first-order test; note a deterministic signer (FIPS 204
      default) yields identical bytes, so this mode only surfaces leakage that
      does not depend on signature content varying.
    """

    # A fixed message all verifications run against (the C shim holds m fixed
    # and only the signature bytes vary between classes).
    FIXED_MSG = b"LatticeScope ML-DSA TVLA fixed message"

    def __init__(self, target: SignTarget, cfg: TvlaConfig):
        super().__init__(cfg)
        self.t = target
        self.msg = self.FIXED_MSG

        # Fixed key material + the fixed Class-A signature, minted once from the
        # target itself (keygen + sign), same philosophy as the KEM path.
        self.pk, self.sk = target.keypair()
        valid_sig = target.sign(self.msg, self.sk)
        self.fixed_valid_sig = valid_sig
        self.fixed_invalid_sig = self._corrupt(valid_sig)

        self._pk_buf = (ctypes.c_uint8 * self.t.pk_len)(*self.pk)
        self._m_buf = (ctypes.c_uint8 * len(self.msg))(*self.msg)

    def _corrupt(self, sig: bytes) -> bytes:
        """Flip a byte near the front so verify rejects and takes the reject
        path (the front carries the c~/challenge in the ML-DSA sig layout)."""
        b = bytearray(sig)
        b[0] ^= 0xFF
        return bytes(b)

    def _class_a_sig(self) -> bytes:
        if self.cfg.mode == "fixed-random":
            return self.fixed_valid_sig
        if self.cfg.rerandomize_invalid:
            return self._corrupt(self.t.sign(self.msg, self.sk))
        return self.fixed_invalid_sig

    def _class_b_sig(self) -> bytes:
        return self.t.sign(self.msg, self.sk)   # fresh valid signature

    def _measure_batch(self, n: int):
        """Build an interleaved A/B schedule of signatures, time in C."""
        sig_len = self.t.sig_len
        labels = bytearray(n)
        blob = bytearray(n * sig_len)
        for i in range(n):
            is_a = (self.rng.random() < 0.5)
            labels[i] = 1 if is_a else 0
            sig = self._class_a_sig() if is_a else self._class_b_sig()
            sig = sig[:sig_len].ljust(sig_len, b"\0")
            blob[i * sig_len:(i + 1) * sig_len] = sig

        sigs = (ctypes.c_uint8 * len(blob)).from_buffer(blob)
        out = (ctypes.c_uint64 * n)()
        rc = self.lib.ct_time_verify(
            ctypes.c_void_p(self.t.verify_addr),
            self._pk_buf,
            self._m_buf, ctypes.c_size_t(len(self.msg)),
            sigs, ctypes.c_size_t(sig_len),
            ctypes.c_size_t(n),
            ctypes.c_uint(self.cfg.warmup),
            out,
        )
        if rc != 0:
            raise RuntimeError("ct_time_verify failed (bad argument to shim)")
        return labels, out


class _SeededRng:
    """Deterministic RNG wrapper exposing the .random() API we use."""
    def __init__(self, seed: int):
        import random
        self._r = random.Random(seed)
    def random(self) -> float:
        return self._r.random()


if __name__ == "__main__":
    # Self-check for the calibrated verdict: a stream whose cumulative |t|
    # spikes far above the threshold early and then settles back to ~0 must NOT
    # be flagged as leaking at the end. This is the H0 optional-stopping trap --
    # if the verdict ever reverts to gating on the running max (peeking) instead
    # of the full-stream t, this assertion fails.
    class _Scripted(_StreamingLeakTest):
        def __init__(self, batches):
            self._batches = batches
            self._i = 0
            self.cfg = TvlaConfig(batch=len(batches[0][0]),
                                  max_iterations=sum(len(l) for l, _ in batches),
                                  crop_enabled=False, threshold=4.5)
            self.welch = WelchTest()
            self._crop_thr = float("inf")
            self._crop_samples = []

        def _measure_batch(self, n):
            labels, cycles = self._batches[self._i]
            self._i += 1
            return labels, cycles

    def _batch(a_mean, b_mean):
        # 100 class-A then 100 class-B samples, each ±1 so variance is nonzero.
        labels = bytearray(200)
        cycles = [0] * 200
        for i in range(200):
            jitter = 1 if i % 2 else -1
            if i < 100:
                labels[i] = 1
                cycles[i] = a_mean + jitter
            else:
                labels[i] = 0
                cycles[i] = b_mean + jitter
        return labels, cycles

    # Batch 1: A slow / B fast (t spikes high). Batch 2: the exact opposite, so
    # both classes end symmetric -> full-stream diff and t collapse to 0.
    scripted = _Scripted([_batch(110, 90), _batch(90, 110)])
    snaps = list(scripted.run())
    peak = max(s.max_abs_t for s in snaps)
    final = snaps[-1]
    assert peak > 4.5, f"expected an early transient crossing, peak={peak:.2f}"
    assert abs(final.t) < 4.5, f"final |t| should settle, got {final.t:.2f}"
    assert not final.leaking, "calibrated verdict must not flag a settled stream"
    print(f"tvla.py verdict self-check OK  (peak max|t|={peak:.1f} crossed, "
          f"final |t|={abs(final.t):.2f} < 4.5 -> clean)")