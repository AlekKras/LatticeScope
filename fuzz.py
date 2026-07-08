"""
fuzz.py -- fork-isolated execution harness and crash triage.

Design decision: crashes are caught by *process isolation*, not by trapping
SIGSEGV in-process. Continuing a Python process after it (via a ctypes call)
has scribbled over memory is undefined behaviour; the honest, production-grade
approach is to run test cases in a forked child and observe its termination
signal from the parent. A shared (MAP_SHARED anonymous) mmap byte-counter is
bumped by the child *before* each call, so when the child dies from SIGSEGV /
SIGBUS / SIGFPE the parent reads the counter and knows the exact offending case
-- no bisection, and the rest of the batch's cost is amortised across a single
fork.

SIGALRM gives us hang detection: a batch that exceeds its time budget is killed
and the case in flight (per the counter) is recorded as a hang.

Crash-triggering inputs are de-duplicated by (signal, payload-prefix hash) and
written to a corpus directory as both a JSON report (strategy, seed, signal,
touched coefficients, hex) and a raw .bin for direct replay against the target.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import mmap
import os
import signal
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from .mutators import Case, Scheduler
from .target import KemTarget


SIGNAL_NAMES = {
    signal.SIGSEGV: "SIGSEGV",
    signal.SIGBUS: "SIGBUS",
    signal.SIGFPE: "SIGFPE",
    signal.SIGABRT: "SIGABRT",
    signal.SIGILL: "SIGILL",
    signal.SIGALRM: "SIGALRM(hang)",
}
CRASH_SIGNALS = {signal.SIGSEGV, signal.SIGBUS, signal.SIGFPE,
                 signal.SIGABRT, signal.SIGILL}


@dataclass
class FuzzConfig:
    surface: str = "ct"              # "ct" (fuzz crypto_kem_dec) or "poly" (leaf)
    max_iterations: int = 5_000_000
    batch: int = 512                 # cases per fork
    batch_time_budget: float = 5.0   # seconds before SIGALRM (hang guard)
    out_dir: str = "latticescope_crashes"
    seed: int = 0
    field_bits: int = 12             # poly surface: 12-bit Kyber coefficients
    # poly-surface leaf ABI: void fn(uint8_t *out, const uint8_t *in)
    leaf_in_len: int = 0
    leaf_out_len: int = 0
    stop_on_first: bool = False


@dataclass
class CrashRecord:
    strategy: str
    signal_name: str
    signum: int
    seed: int
    domain: str
    payload_hex: str
    touched: List[int]
    detail: str
    path: str


@dataclass
class FuzzSnapshot:
    iterations: int
    exec_per_s: float
    current_strategy: str
    crashes: int
    unique_crashes: int
    last_crash: Optional[CrashRecord]
    forks: int


class LatticeFuzzer:
    def __init__(self, target: KemTarget, cfg: FuzzConfig,
                 leaf_addr: Optional[int] = None):
        self.t = target
        self.cfg = cfg
        self.leaf_addr = leaf_addr
        self.out_dir = Path(cfg.out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Fixed secret material for the ct surface; the target's own keygen/enc
        # provides a structurally valid seed ciphertext to mutate.
        base_ct = None
        self._sk_buf = None
        self._ss_buf = None
        if cfg.surface == "ct":
            self.pk, self.sk = target.keypair()
            base_ct, _ = target.enc(self.pk)
            self._payload_len = target.ct_len
            self._sk_buf = (ctypes.c_uint8 * target.sk_len)(*self.sk)
            self._ss_buf = (ctypes.c_uint8 * target.ss_len)()
        else:
            if leaf_addr is None or cfg.leaf_in_len == 0 or cfg.leaf_out_len == 0:
                raise ValueError("poly surface requires leaf_addr, leaf_in_len, "
                                 "leaf_out_len")
            self._payload_len = cfg.leaf_in_len
            self._out_buf = (ctypes.c_uint8 * cfg.leaf_out_len)()
            self._leaf = ctypes.CFUNCTYPE(
                None, ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8))(leaf_addr)

        self.sched = Scheduler(cfg.surface, target.params, base_ct,
                               cfg.seed, cfg.field_bits)

        # MAP_SHARED anonymous page: the child's progress is visible to us.
        self._counter = mmap.mmap(-1, 8)

        self._seen: Dict[str, CrashRecord] = {}
        self._crash_count = 0

    # -- calling the target on one payload (runs in child) --------------
    def _invoke(self, payload: bytes) -> None:
        if self.cfg.surface == "ct":
            n = self._payload_len
            ct_buf = (ctypes.c_uint8 * n).from_buffer_copy(
                payload[:n].ljust(n, b"\0"))
            self.t._dec(self._ss_buf, ct_buf, self._sk_buf)
        else:
            n = self._payload_len
            in_buf = (ctypes.c_uint8 * n).from_buffer_copy(
                payload[:n].ljust(n, b"\0"))
            self._leaf(self._out_buf, in_buf)

    # -- run a batch in a forked child ----------------------------------
    def _run_batch(self, cases: List[Case]):
        """Return (status, signum, idx). status in {ok, crash, hang}."""
        self._counter[:8] = struct.pack("Q", 0)
        pid = os.fork()
        if pid == 0:
            # ---- child ----
            # Arm a hang guard for the whole batch.
            try:
                signal.alarm(0)
                signal.setitimer(signal.ITIMER_REAL, self.cfg.batch_time_budget)
            except (ValueError, OSError):
                pass
            i = 0
            try:
                for i, case in enumerate(cases):
                    # Record progress BEFORE the call so a fault points at i.
                    self._counter[:8] = struct.pack("Q", i)
                    self._invoke(case.payload)
            except SystemExit:
                os._exit(0)
            except BaseException:
                # A Python-level exception is not a native crash; note the index
                # via a high bit and exit cleanly so the parent can skip it.
                self._counter[:8] = struct.pack("Q", i | (1 << 63))
                os._exit(0)
            os._exit(0)

        # ---- parent ----
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            idx = struct.unpack("Q", self._counter[:8])[0] & ~(1 << 63)
            if sig == signal.SIGALRM:
                return ("hang", sig, idx)
            return ("crash", sig, idx)
        return ("ok", None, None)

    # -- persist a crash -------------------------------------------------
    def _record_crash(self, case: Case, signum: int) -> CrashRecord:
        prefix = hashlib.sha256(case.payload[:32]).hexdigest()[:12]
        key = f"{signum}:{prefix}"
        if key in self._seen:
            return self._seen[key]

        sig_name = SIGNAL_NAMES.get(signum, f"SIG{signum}")
        stem = f"crash_{sig_name.split('(')[0]}_{prefix}"
        bin_path = self.out_dir / f"{stem}.bin"
        json_path = self.out_dir / f"{stem}.json"
        bin_path.write_bytes(case.payload)

        rec = CrashRecord(
            strategy=case.strategy,
            signal_name=sig_name,
            signum=signum,
            seed=case.seed,
            domain=case.domain,
            payload_hex=case.payload.hex(),
            touched=case.touched,
            detail=case.detail,
            path=str(bin_path),
        )
        json_path.write_text(json.dumps({
            "strategy": rec.strategy,
            "signal": rec.signal_name,
            "seed": rec.seed,
            "domain": rec.domain,
            "detail": rec.detail,
            "touched_coefficients": rec.touched,
            "payload_len": len(case.payload),
            "payload_bin": str(bin_path),
            "payload_hex": rec.payload_hex,
        }, indent=2))
        self._seen[key] = rec
        return rec

    def _confirm_single(self, case: Case) -> Optional[int]:
        """Replay one case in its own fork to confirm the crash reproduces."""
        status, signum, _ = self._run_batch([case])
        if status == "crash":
            return signum
        return None

    # -- main streaming loop --------------------------------------------
    def run(self) -> Iterator[FuzzSnapshot]:
        done = 0
        forks = 0
        last_crash: Optional[CrashRecord] = None
        current_strategy = "(starting)"
        start = time.perf_counter()

        while done < self.cfg.max_iterations:
            n = min(self.cfg.batch, self.cfg.max_iterations - done)
            cases = [self.sched.next_case() for _ in range(n)]
            current_strategy = cases[-1].describe()

            status, signum, idx = self._run_batch(cases)
            forks += 1

            if status in ("crash", "hang") and idx < len(cases):
                offender = cases[idx]
                confirmed = signum
                if status == "crash":
                    c = self._confirm_single(offender)
                    forks += 1
                    if c is not None:
                        confirmed = c
                last_crash = self._record_crash(offender, confirmed)
                self._crash_count += 1
                # Resume after the offending case within this batch.
                done += idx + 1
                if self.cfg.stop_on_first:
                    yield self._snap(done, start, current_strategy, last_crash, forks)
                    return
            else:
                done += n

            yield self._snap(done, start, current_strategy, last_crash, forks)

    def _snap(self, done, start, strat, last_crash, forks) -> FuzzSnapshot:
        elapsed = max(time.perf_counter() - start, 1e-9)
        return FuzzSnapshot(
            iterations=done,
            exec_per_s=done / elapsed,
            current_strategy=strat,
            crashes=self._crash_count,
            unique_crashes=len(self._seen),
            last_crash=last_crash,
            forks=forks,
        )