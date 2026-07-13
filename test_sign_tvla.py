"""
test_sign_tvla.py -- self-check for the ML-DSA signature-timing (sign-tvla) path.

Builds the intentionally-flawed demo/vuln_dsa.c and asserts that:
  * fixed-invalid mode FLAGS the planted non-constant-time reject path, and
  * a control run (fixed-random, both classes valid -> accept path) does NOT
    flag -- so the test can actually fail, not just always report a leak.

Run directly (no framework needed):  python test_sign_tvla.py
Also discoverable by pytest.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from latticescope.lattice import SIGN_SETS
from latticescope.target import SignTarget
from latticescope.tvla import SignLeakageTest, TvlaConfig


def _build_demo_dsa(workdir: Path) -> Path:
    src = _ROOT / "demo" / "vuln_dsa.c"
    assert src.is_file(), f"demo source missing: {src}"
    so = workdir / "libvuln_dsa.so"
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-O2", "-fPIC", "-shared", "-Wall", str(src), "-o", str(so)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"build failed:\n{proc.stderr}"
    return so


def _run(so: Path, mode: str, max_iterations: int, stop_on_leak: bool):
    target = SignTarget(str(so), SIGN_SETS["ml-dsa-65"])
    cfg = TvlaConfig(mode=mode, max_iterations=max_iterations, batch=512,
                     threshold=4.5, stop_on_leak=stop_on_leak, seed=1)
    test = SignLeakageTest(target, cfg)
    final = None
    for snap in test.run():
        final = snap
        if stop_on_leak and snap.leaking:
            break
    return final


def test_sign_tvla_flags_planted_leak():
    with tempfile.TemporaryDirectory(prefix="latticescope_signtvla_") as d:
        so = _build_demo_dsa(Path(d))
        final = _run(so, "fixed-invalid", max_iterations=200_000, stop_on_leak=True)
        assert final is not None, "no snapshot produced"
        assert final.leaking, f"expected a leak, got max|t|={final.max_abs_t:.2f}"


def test_sign_tvla_control_does_not_flag():
    # Both classes are valid signatures -> accept path -> no branch divergence.
    with tempfile.TemporaryDirectory(prefix="latticescope_signtvla_") as d:
        so = _build_demo_dsa(Path(d))
        final = _run(so, "fixed-random", max_iterations=100_000, stop_on_leak=False)
        assert final is not None, "no snapshot produced"
        assert not final.leaking, (
            f"control unexpectedly flagged a leak: max|t|={final.max_abs_t:.2f}")


if __name__ == "__main__":
    test_sign_tvla_flags_planted_leak()
    print("PASS: fixed-invalid flags the planted verify-timing leak")
    test_sign_tvla_control_does_not_flag()
    print("PASS: fixed-random control stays under the threshold")
    print("\nALL SIGN-TVLA SELF-CHECKS PASSED")
