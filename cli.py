"""
cli.py -- LatticeScope command-line entry point.

Subcommands
-----------
  tvla          Test Vector Leakage Assessment on ML-KEM decapsulation.
  sign-tvla     Test Vector Leakage Assessment on ML-DSA signature verify.
  fuzz-lattice  Structure-aware algebraic/NTT fuzzer for ML-KEM (dec surface)
                or a named leaf function (poly surface).
  selftest      Build the bundled intentionally-flawed demo target and run both
                modules against it end-to-end (no external target needed).

Every subcommand takes --lib <path-to-target.so> except selftest, which builds
its own. See README.md for the expected target ABI and measurement setup.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .lattice import KEM_SETS, SIGN_SETS


def _add_common_target(sp):
    sp.add_argument("--lib", required=True,
                    help="path to the target shared object (.so)")
    sp.add_argument("--param", default="ml-kem-768", choices=sorted(KEM_SETS),
                    help="ML-KEM parameter set (default: ml-kem-768)")
    sp.add_argument("--sym-keypair", default=None,
                    help="explicit crypto_kem_keypair symbol name")
    sp.add_argument("--sym-enc", default=None,
                    help="explicit crypto_kem_enc symbol name")
    sp.add_argument("--sym-dec", default=None,
                    help="explicit crypto_kem_dec symbol name")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="latticescope",
        description="PQC implementation assurance: TVLA timing analysis and "
                    "structure-aware algebraic fuzzing for ML-KEM / ML-DSA.")
    sub = p.add_subparsers(dest="cmd", required=True)

    # -- tvla ------------------------------------------------------------
    t = sub.add_parser("tvla", help="TVLA timing leakage assessment (--tvla)")
    _add_common_target(t)
    t.add_argument("--mode", default="fixed-invalid",
                   choices=["fixed-invalid", "fixed-random"],
                   help="class split (default: fixed-invalid)")
    t.add_argument("--iterations", type=int, default=2_000_000,
                   help="max decapsulations to measure")
    t.add_argument("--batch", type=int, default=4096,
                   help="measurements per C timing call")
    t.add_argument("--warmup", type=int, default=64,
                   help="untimed calls before each batch")
    t.add_argument("--threshold", type=float, default=4.5,
                   help="|t| flag threshold (default: 4.5)")
    t.add_argument("--crop-pct", type=float, default=99.5,
                   help="drop cycle samples above this percentile")
    t.add_argument("--no-crop", action="store_true",
                   help="disable outlier cropping")
    t.add_argument("--core", type=int, default=None,
                   help="CPU core to pin to (default: highest available)")
    t.add_argument("--rerandomize-invalid", action="store_true",
                   help="use fresh invalid ciphertexts for class A each time")
    t.add_argument("--stop-on-leak", action="store_true",
                   help="halt as soon as |t| crosses the threshold")
    t.add_argument("--seed", type=int, default=None,
                   help="deterministic class-scheduling seed")

    # -- sign-tvla -------------------------------------------------------
    st = sub.add_parser("sign-tvla",
                        help="TVLA timing leakage on ML-DSA signature verify")
    st.add_argument("--lib", required=True,
                    help="path to the target shared object (.so)")
    st.add_argument("--param", default="ml-dsa-65", choices=sorted(SIGN_SETS),
                    help="ML-DSA parameter set (default: ml-dsa-65)")
    st.add_argument("--sym-verify", default=None,
                    help="explicit crypto_sign_verify symbol name")
    st.add_argument("--sym-keypair", default=None,
                    help="explicit crypto_sign_keypair symbol name")
    st.add_argument("--sym-sign", default=None,
                    help="explicit crypto_sign_signature symbol name")
    st.add_argument("--mode", default="fixed-invalid",
                    choices=["fixed-invalid", "fixed-random"],
                    help="class split (default: fixed-invalid)")
    st.add_argument("--iterations", type=int, default=2_000_000,
                    help="max verifications to measure")
    st.add_argument("--batch", type=int, default=1024,
                    help="measurements per C timing call")
    st.add_argument("--warmup", type=int, default=64,
                    help="untimed calls before each batch")
    st.add_argument("--threshold", type=float, default=4.5,
                    help="|t| flag threshold (default: 4.5)")
    st.add_argument("--crop-pct", type=float, default=99.5,
                    help="drop cycle samples above this percentile")
    st.add_argument("--no-crop", action="store_true",
                    help="disable outlier cropping")
    st.add_argument("--core", type=int, default=None,
                    help="CPU core to pin to (default: highest available)")
    st.add_argument("--rerandomize-invalid", action="store_true",
                    help="use fresh invalid signatures for class A each time")
    st.add_argument("--stop-on-leak", action="store_true",
                    help="halt as soon as |t| crosses the threshold")
    st.add_argument("--seed", type=int, default=None,
                    help="deterministic class-scheduling seed")

    # -- fuzz-lattice ----------------------------------------------------
    f = sub.add_parser("fuzz-lattice",
                       help="structure-aware algebraic/NTT fuzzer (--fuzz-lattice)")
    _add_common_target(f)
    f.add_argument("--surface", default="ct", choices=["ct", "poly"],
                   help="ct = fuzz crypto_kem_dec; poly = fuzz a leaf function")
    f.add_argument("--iterations", type=int, default=5_000_000,
                   help="max test cases")
    f.add_argument("--batch", type=int, default=512,
                   help="cases per forked child")
    f.add_argument("--batch-timeout", type=float, default=5.0,
                   help="seconds before a batch is treated as a hang")
    f.add_argument("--out", default="latticescope_crashes",
                   help="directory for crash corpus")
    f.add_argument("--seed", type=int, default=0,
                   help="master mutation seed (reproducible)")
    f.add_argument("--stop-on-first", action="store_true",
                   help="stop after the first unique crash")
    # poly-surface leaf options
    f.add_argument("--sym-fn", default=None,
                   help="poly surface: leaf symbol, ABI void fn(uint8_t*out, "
                        "const uint8_t*in)")
    f.add_argument("--in-len", type=int, default=0,
                   help="poly surface: leaf input length in bytes")
    f.add_argument("--out-len", type=int, default=0,
                   help="poly surface: leaf output length in bytes")
    f.add_argument("--field-bits", type=int, default=12,
                   help="poly surface: coefficient bit width (Kyber=12)")

    # -- selftest --------------------------------------------------------
    s = sub.add_parser("selftest",
                       help="build the flawed demo target and exercise both modules")
    s.add_argument("--iterations", type=int, default=500_000,
                   help="TVLA iteration cap for the self-test")
    s.add_argument("--fuzz-iterations", type=int, default=50_000,
                   help="fuzz iteration cap for the self-test")
    return p


def _run_tvla(args) -> int:
    from .lattice import KEM_SETS
    from .target import KemTarget
    from .tvla import KemLeakageTest, TvlaConfig
    from .ui import run_tvla_ui

    target = KemTarget(args.lib, KEM_SETS[args.param],
                       keypair_sym=args.sym_keypair,
                       enc_sym=args.sym_enc, dec_sym=args.sym_dec)
    cfg = TvlaConfig(
        mode=args.mode, max_iterations=args.iterations, batch=args.batch,
        warmup=args.warmup, threshold=args.threshold,
        crop_percentile=args.crop_pct, crop_enabled=not args.no_crop,
        core=args.core, rerandomize_invalid=args.rerandomize_invalid,
        stop_on_leak=args.stop_on_leak, seed=args.seed)
    test = KemLeakageTest(target, cfg)
    final = run_tvla_ui(test, cfg, target)
    return 2 if (final and final.leaking) else 0


def _run_sign_tvla(args) -> int:
    from .lattice import SIGN_SETS
    from .target import SignTarget
    from .tvla import SignLeakageTest, TvlaConfig
    from .ui import run_tvla_ui

    target = SignTarget(args.lib, SIGN_SETS[args.param],
                        verify_sym=args.sym_verify,
                        keypair_sym=args.sym_keypair,
                        sign_sym=args.sym_sign)
    cfg = TvlaConfig(
        mode=args.mode, max_iterations=args.iterations, batch=args.batch,
        warmup=args.warmup, threshold=args.threshold,
        crop_percentile=args.crop_pct, crop_enabled=not args.no_crop,
        core=args.core, rerandomize_invalid=args.rerandomize_invalid,
        stop_on_leak=args.stop_on_leak, seed=args.seed)
    test = SignLeakageTest(target, cfg)
    final = run_tvla_ui(test, cfg, target)
    return 2 if (final and final.leaking) else 0


def _run_fuzz(args) -> int:
    from .lattice import KEM_SETS
    from .target import KemTarget
    from .fuzz import FuzzConfig, LatticeFuzzer
    from .ui import run_fuzz_ui

    target = KemTarget(args.lib, KEM_SETS[args.param],
                       keypair_sym=args.sym_keypair,
                       enc_sym=args.sym_enc, dec_sym=args.sym_dec)

    leaf_addr = None
    if args.surface == "poly":
        if not args.sym_fn or args.in_len <= 0 or args.out_len <= 0:
            print("error: poly surface requires --sym-fn, --in-len, --out-len",
                  file=sys.stderr)
            return 1
        import ctypes
        fn = getattr(target.lib, args.sym_fn)
        leaf_addr = ctypes.cast(fn, ctypes.c_void_p).value

    cfg = FuzzConfig(
        surface=args.surface, max_iterations=args.iterations, batch=args.batch,
        batch_time_budget=args.batch_timeout, out_dir=args.out, seed=args.seed,
        field_bits=args.field_bits, leaf_in_len=args.in_len,
        leaf_out_len=args.out_len, stop_on_first=args.stop_on_first)
    fuzzer = LatticeFuzzer(target, cfg, leaf_addr=leaf_addr)
    final = run_fuzz_ui(fuzzer, cfg, target)
    return 2 if (final and final.unique_crashes) else 0


def _run_selftest(args) -> int:
    from .selftest import run_selftest
    return run_selftest(args.iterations, args.fuzz_iterations)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "tvla":
            return _run_tvla(args)
        if args.cmd == "sign-tvla":
            return _run_sign_tvla(args)
        if args.cmd == "fuzz-lattice":
            return _run_fuzz(args)
        if args.cmd == "selftest":
            return _run_selftest(args)
    except (OSError, AttributeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())