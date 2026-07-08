"""
LatticeScope -- PQC implementation-assurance tooling.

Two modules for auditing your *own* compiled ML-KEM / ML-DSA builds:

  * TVLA microarchitectural timing-leakage detection (tvla, ui, stats, cshim)
  * structure-aware algebraic / NTT fuzzing with fork isolation (fuzz, mutators)

Everything targets code you control (a .so you built from reference sources,
PQClean, liboqs, a vendor SDK). Nothing here attacks a remote party; it finds
constant-time and memory-safety defects in an implementation before shipping.

See README.md for the expected target ABI and measurement setup.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .lattice import KEM_SETS, SIGN_SETS, KemParams, SignParams
from .target import KemTarget, SignTarget
from .tvla import KemLeakageTest, TvlaConfig, TvlaSnapshot
from .fuzz import FuzzConfig, LatticeFuzzer, FuzzSnapshot, CrashRecord
from .mutators import Case, Scheduler

__all__ = [
    "__version__",
    "KEM_SETS", "SIGN_SETS", "KemParams", "SignParams",
    "KemTarget", "SignTarget",
    "KemLeakageTest", "TvlaConfig", "TvlaSnapshot",
    "FuzzConfig", "LatticeFuzzer", "FuzzSnapshot", "CrashRecord",
    "Case", "Scheduler",
]