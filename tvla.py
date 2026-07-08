"""
tvla.py -- Test Vector Leakage Assessment for ML-KEM decapsulation.

Method
------
We split inputs into two classes and time decapsulation of each under
identical conditions, interleaving classes within every batch so that slow
drift (thermal, frequency) affects both equally and cancels in the difference.
A streaming Welch's t-test tracks the divergence; |t| > threshold (4.5 by
convention) is the flag for a data-dependent, i.e. potentially exploitable,
timing leak.

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
from .target import KemTarget


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


class KemLeakageTest:
    def __init__(self, target: KemTarget, cfg: TvlaConfig):
        self.t = target
        self.cfg = cfg
        self.lib = build_shim.load()
        self.rng = secrets.SystemRandom() if cfg.seed is None else _SeededRng(cfg.seed)

        # Fixed key material and the fixed Class-A ciphertext, generated once
        # from the target itself.
        self.pk, self.sk = target.keypair()
        valid_ct, _ = target.enc(self.pk)
        self.fixed_valid_ct = valid_ct
        self.fixed_invalid_ct = self._corrupt(valid_ct)

        self._sk_buf = (ctypes.c_uint8 * self.t.sk_len)(*self.sk)
        self.welch = WelchTest()
        self._crop_thr = float("inf")
        self._crop_samples: List[int] = []

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
                leaking=max_abs_t > self.cfg.threshold,
                pinned_core=pinned_core,
            )


class _SeededRng:
    """Deterministic RNG wrapper exposing the .random() API we use."""
    def __init__(self, seed: int):
        import random
        self._r = random.Random(seed)
    def random(self) -> float:
        return self._r.random()