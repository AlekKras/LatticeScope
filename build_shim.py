"""
build_shim.py -- compile cshim.c into a loadable shared object on first use.

We compile at runtime rather than shipping a binary so the shim always matches
the host CPU/ABI and the user can inspect exactly what is being built. The
result is cached next to the source and only rebuilt when the source changes.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SRC = _HERE / "cshim.c"


def _cc() -> str:
    return os.environ.get("CC", "cc")


def _cache_so_path() -> Path:
    # Namespace the cached object by source hash + interpreter tag so a changed
    # source or a different Python/arch never loads a stale artifact.
    digest = hashlib.sha256(_SRC.read_bytes()).hexdigest()[:16]
    tag = f"{sys.platform}-{os.uname().machine}"
    return _HERE / f"_ctshim.{tag}.{digest}.so"


def build(force: bool = False) -> Path:
    """Compile the shim if needed and return the path to the .so."""
    so = _cache_so_path()
    if so.exists() and not force:
        return so

    # Drop stale caches from prior source edits / interpreter tags so they
    # don't accumulate next to the package indefinitely.
    for stale in _HERE.glob("_ctshim.*.so"):
        if stale != so:
            stale.unlink(missing_ok=True)

    # -O2 for a lean measurement loop; -fno-omit-frame-pointer keeps stacks
    # sane if a user attaches a debugger to a crashing child. We deliberately do
    # NOT harden the shim itself -- it must observe the target faithfully.
    cmd = [
        _cc(),
        "-O2",
        "-fPIC",
        "-shared",
        "-fno-omit-frame-pointer",
        "-Wall",
        "-o", str(so),
        str(_SRC),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "Failed to compile LatticeScope timing shim.\n"
            f"  command: {' '.join(cmd)}\n"
            f"  stderr:\n{proc.stderr}"
        )
    return so


_LOADED: ctypes.CDLL | None = None


def load() -> ctypes.CDLL:
    """Build (if necessary) and dlopen the shim, wiring argtypes/restypes."""
    global _LOADED
    if _LOADED is not None:
        return _LOADED

    lib = ctypes.CDLL(str(build()))

    u8p = ctypes.POINTER(ctypes.c_uint8)
    u64p = ctypes.POINTER(ctypes.c_uint64)
    sz = ctypes.c_size_t

    lib.read_cycles.restype = ctypes.c_uint64
    lib.read_cycles.argtypes = []

    lib.read_cycles_overhead.restype = ctypes.c_uint64
    lib.read_cycles_overhead.argtypes = []

    lib.cs_arch_is_x86.restype = ctypes.c_int
    lib.cs_arch_is_x86.argtypes = []

    lib.ct_time_dec.restype = ctypes.c_int
    lib.ct_time_dec.argtypes = [
        ctypes.c_void_p,  # fn
        u8p,              # sk
        u8p,              # cts
        sz, sz, sz,       # ct_len, ss_len, n
        ctypes.c_uint,    # warmup
        u64p,             # out_cycles
    ]

    lib.ct_time_verify.restype = ctypes.c_int
    lib.ct_time_verify.argtypes = [
        ctypes.c_void_p,  # fn
        u8p,              # pk
        u8p, sz,          # m, mlen
        u8p, sz,          # sigs, sig_len
        sz,               # n
        ctypes.c_uint,    # warmup
        u64p,             # out_cycles
    ]

    lib.ct_time_buf1.restype = ctypes.c_int
    lib.ct_time_buf1.argtypes = [
        ctypes.c_void_p,  # fn
        u8p, sz,          # ins, in_len
        sz,               # out_len
        sz,               # n
        ctypes.c_uint,    # warmup
        u64p,             # out_cycles
    ]

    _LOADED = lib
    return lib


if __name__ == "__main__":
    lib = load()
    print("shim:", _cache_so_path().name)
    print("arch x86:", bool(lib.cs_arch_is_x86()))
    print("counter read overhead (cycles):", lib.read_cycles_overhead())
    a = lib.read_cycles()
    b = lib.read_cycles()
    print("sample delta:", b - a)