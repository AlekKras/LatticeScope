"""
selftest.py -- build the bundled flawed demo target and exercise both modules.

This is the `latticescope selftest` subcommand. It needs no external target: it
compiles demo/vuln_kem.c (an intentionally-flawed stand-in with the ML-KEM-768
ABI and two planted bugs), then:

  1. runs the TVLA module in fixed-invalid mode and checks that Welch's t
     crosses the leak threshold (the planted non-constant-time rejection path);
  2. runs the structure-aware fuzzer on the ciphertext surface and checks that
     it catches a memory fault (the planted out-of-bounds read on the reject
     path) and writes a crash artifact;
  3. builds demo/vuln_dsa.c (an ML-DSA-65 verify stand-in with a planted
     non-constant-time reject path) and runs the signature-timing module,
     checking that Welch's t crosses the leak threshold.

Exit code: 0 if ALL detections fire as expected (the tools work), 1 otherwise.
Note this is the opposite polarity to the `tvla` / `fuzz-lattice` subcommands,
where a *finding* returns 2 -- here, finding the planted bugs is success.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


def _find_demo_source(filename: str = "vuln_kem.c") -> Optional[Path]:
    """Locate a demo source (e.g. vuln_kem.c / vuln_dsa.c) near the tree/CWD."""
    if filename == "vuln_kem.c":
        env = os.environ.get("LATTICESCOPE_DEMO_SRC")
        if env and Path(env).is_file():
            return Path(env)
    pkg = Path(__file__).resolve().parent
    candidates = [
        pkg.parent / "demo" / filename,       # <root>/demo alongside package
        pkg / "demo" / filename,               # bundled inside package
        Path.cwd() / "demo" / filename,
        pkg.parent.parent / "demo" / filename,
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def _build_demo(src: Path, workdir: Path) -> Path:
    """Compile the demo target into workdir and return the .so path."""
    so = workdir / f"lib{src.stem}.so"
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-O2", "-fPIC", "-shared", "-Wall", str(src), "-o", str(so)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "Failed to build demo target.\n"
            f"  command: {' '.join(cmd)}\n  stderr:\n{proc.stderr}")
    return so


def _section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def run_selftest(iterations: int = 500_000,
                 fuzz_iterations: int = 50_000) -> int:
    from .lattice import KEM_SETS, SIGN_SETS
    from .target import KemTarget, SignTarget
    from .tvla import KemLeakageTest, SignLeakageTest, TvlaConfig
    from .fuzz import FuzzConfig, LatticeFuzzer
    from .ui import run_tvla_ui, run_fuzz_ui
    from .build_shim import counter_unit

    unit = counter_unit()

    src = _find_demo_source()
    if src is None:
        print("error: could not locate demo/vuln_kem.c. Expected it alongside "
              "the package or under ./demo. Set LATTICESCOPE_DEMO_SRC to its "
              "path, or run demo/build_demo.sh and point --lib at the result.",
              file=sys.stderr)
        return 1

    params = KEM_SETS["ml-kem-768"]
    tmp = Path(tempfile.mkdtemp(prefix="latticescope_selftest_"))
    print(f"demo source : {src}")
    print(f"work dir    : {tmp}")
    print(f"parameter   : {params.name}  "
          f"(ct={params.ct_bytes} pk={params.pk_bytes} sk={params.sk_bytes})")

    try:
        lib = _build_demo(src, tmp)
        print(f"built       : {lib}")
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    tvla_ok = False
    fuzz_ok = False

    # -- Module 1: TVLA ---------------------------------------------------
    _section("MODULE 1 — TVLA timing leakage (expect: LEAK on reject path)")
    target = KemTarget(str(lib), params)
    tvla_cfg = TvlaConfig(mode="fixed-invalid", max_iterations=iterations,
                          threshold=4.5, stop_on_leak=True)
    tvla_test = KemLeakageTest(target, tvla_cfg)
    tvla_final = run_tvla_ui(tvla_test, tvla_cfg, target)
    if tvla_final is not None and tvla_final.leaking:
        tvla_ok = True
        print(f"\nRESULT: LEAK DETECTED  max|t|={tvla_final.max_abs_t:.2f} "
              f"> {tvla_cfg.threshold}  Δ={tvla_final.diff:+.1f} {unit}  "
              f"p={tvla_final.p_value:.1e}  (as expected)")
    else:
        mt = tvla_final.max_abs_t if tvla_final else float("nan")
        print(f"\nRESULT: no leak flagged (max|t|={mt:.2f}) — UNEXPECTED. Try a "
              f"larger --iterations or a quieter core.")

    # -- Module 2: structure-aware fuzzer --------------------------------
    _section("MODULE 2 — structure-aware fuzzer (expect: SIGSEGV, OOB read)")
    fuzz_target = KemTarget(str(lib), params)
    crash_dir = tmp / "crashes"
    fuzz_cfg = FuzzConfig(surface="ct", max_iterations=fuzz_iterations,
                          batch=256, out_dir=str(crash_dir), seed=1,
                          stop_on_first=True)
    fuzzer = LatticeFuzzer(fuzz_target, fuzz_cfg)
    fuzz_final = run_fuzz_ui(fuzzer, fuzz_cfg, fuzz_target)
    if fuzz_final is not None and fuzz_final.unique_crashes > 0:
        fuzz_ok = True
        c = fuzz_final.last_crash
        print(f"\nRESULT: CRASH FOUND  {c.signal_name} via {c.strategy} "
              f"after {fuzz_final.iterations:,} cases  (as expected)")
        print(f"        artifact: {c.path}")
        arts = sorted(str(p) for p in crash_dir.glob("*"))
        if arts:
            print("        corpus  : " + ", ".join(Path(a).name for a in arts))
    else:
        print(f"\nRESULT: no crash found in {fuzz_iterations:,} cases — "
              f"UNEXPECTED. Try a larger --fuzz-iterations.")

    # -- Module 1 (signatures): ML-DSA verify timing ---------------------
    _section("MODULE 1 (ML-DSA) — verify timing leakage (expect: LEAK on reject path)")
    sign_ok = False
    dsa_src = _find_demo_source("vuln_dsa.c")
    if dsa_src is None:
        print("error: could not locate demo/vuln_dsa.c — cannot run the ML-DSA "
              "verify-timing check.", file=sys.stderr)
    else:
        try:
            dsa_lib = _build_demo(dsa_src, tmp)
            print(f"built       : {dsa_lib}")
            sparams = SIGN_SETS["ml-dsa-65"]
            sign_target = SignTarget(str(dsa_lib), sparams)
            sign_cfg = TvlaConfig(mode="fixed-invalid", max_iterations=iterations,
                                  threshold=4.5, stop_on_leak=True)
            sign_test = SignLeakageTest(sign_target, sign_cfg)
            sign_final = run_tvla_ui(sign_test, sign_cfg, sign_target)
            if sign_final is not None and sign_final.leaking:
                sign_ok = True
                print(f"\nRESULT: LEAK DETECTED  max|t|={sign_final.max_abs_t:.2f} "
                      f"> {sign_cfg.threshold}  Δ={sign_final.diff:+.1f} {unit}  "
                      f"p={sign_final.p_value:.1e}  (as expected)")
            else:
                mt = sign_final.max_abs_t if sign_final else float("nan")
                print(f"\nRESULT: no leak flagged (max|t|={mt:.2f}) — UNEXPECTED. "
                      f"Try a larger --iterations or a quieter core.")
        except (OSError, AttributeError, RuntimeError) as e:
            print(f"error: ML-DSA verify-timing check failed: {e}", file=sys.stderr)

    # -- Summary ----------------------------------------------------------
    _section("SELF-TEST SUMMARY")
    print(f"  TVLA  leak  detection (KEM) : {'PASS' if tvla_ok else 'FAIL'}")
    print(f"  Fuzz  crash detection (KEM) : {'PASS' if fuzz_ok else 'FAIL'}")
    print(f"  TVLA  leak  detection (DSA) : {'PASS' if sign_ok else 'FAIL'}")
    ok = tvla_ok and fuzz_ok and sign_ok
    print(f"\n  overall: {'PASS — all modules behaved as designed' if ok else 'FAIL'}")
    print(f"  (artifacts left in {tmp})")
    return 0 if ok else 1