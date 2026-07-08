"""
mutators.py -- structure- and algebra-aware input generation.

Generic byte-flippers waste cycles because they corrupt the wire format before
execution ever reaches the interesting modular-arithmetic and NTT code. These
mutators instead target the mathematical invariants of lattice schemes, so the
malformation survives parsing and stresses the arithmetic itself.

Two payload domains:
  * "ct"   -- a full ML-KEM ciphertext (fixed length). Mutations respect the
              du/dv packing so the decoder accepts the structure, then push the
              compressed coefficients and raw bytes to their edges.
  * "poly" -- a 12-bit-packed polynomial, the input to a leaf like
              poly_frombytes. Here decoded coefficients can legitimately land
              in (Q, 4095], i.e. UN-REDUCED and above the modulus. Reference
              Kyber does not reduce on frombytes, so these values flow straight
              into the NTT / basemul -- this is where "coefficient above Q into
              the NTT" is a real, reachable condition.

Every case carries reproducibility metadata (strategy + seed + touched
coefficients) so a crash can be replayed and understood.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import lattice as L


# Byte values that historically expose edge bugs in parsers/arithmetic.
INTERESTING_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
# 16-/32-bit signed extremes as little-endian byte patterns.
INT16_EXTREMES = [(0x00, 0x80), (0xFF, 0x7F)]                     # INT16_MIN/MAX
INT32_EXTREMES = [(0x00, 0x00, 0x00, 0x80), (0xFF, 0xFF, 0xFF, 0x7F)]


@dataclass
class Case:
    payload: bytes
    strategy: str
    seed: int
    domain: str                       # "ct" or "poly"
    touched: List[int] = field(default_factory=list)   # coefficient indices
    detail: str = ""

    def describe(self) -> str:
        base = f"{self.strategy}"
        if self.detail:
            base += f" [{self.detail}]"
        return base


# ---------------------------------------------------------------------------
# Coefficient-domain mutations
# ---------------------------------------------------------------------------

def _q_boundary_values(q: int, field_bits: int) -> List[int]:
    """Values on/around the modulus that fit in `field_bits`."""
    mask = (1 << field_bits) - 1
    cands = {0, 1, 2, mask - 1, mask, q, q + 1, q - 1, 2 * q - 1, 2 * q}
    return sorted(v & mask for v in cands)


def montgomery_boundary_poly(rng: random.Random, q: int, n: int,
                             field_bits: int, seed: int) -> Case:
    """Set a spread of coefficients to modulus-boundary values, then pack.

    Forces the reduction loop to handle inputs precisely at Q, Q+1, 2Q-1 and
    the field extremes -- the classic trigger for unhandled over-/under-
    reduction in Montgomery/Barrett code.
    """
    vals = _q_boundary_values(q, field_bits)
    coeffs = [rng.randrange(1 << field_bits) for _ in range(n)]
    touched = []
    k = rng.randint(1, max(1, n // 4))
    for _ in range(k):
        idx = rng.randrange(n)
        coeffs[idx] = rng.choice(vals)
        touched.append(idx)
    payload = L.byte_encode(coeffs, field_bits)
    return Case(payload, "Montgomery/Barrett Boundary Stress", seed, "poly",
                sorted(set(touched)),
                detail=f"{len(touched)} coeffs pinned near Q={q}")


def ntt_domain_malform_poly(rng: random.Random, q: int, n: int,
                            field_bits: int, seed: int) -> Case:
    """Fill the polynomial with UN-REDUCED coefficients in (Q, 2^field_bits).

    Maximizes the chance that a subsequent butterfly/basemul yields a value
    outside the bound the next NTT layer assumes, exposing missing reductions.
    """
    hi_lo, hi_hi = q + 1, (1 << field_bits) - 1
    if hi_lo > hi_hi:                     # field too narrow to exceed Q
        hi_lo = hi_hi
    style = rng.choice(["all-max", "all-qplus", "random-over", "alternating"])
    if style == "all-max":
        coeffs = [hi_hi] * n
    elif style == "all-qplus":
        coeffs = [q + 1] * n
    elif style == "alternating":
        coeffs = [hi_hi if i % 2 else q for i in range(n)]
    else:
        coeffs = [rng.randint(hi_lo, hi_hi) for _ in range(n)]
    payload = L.byte_encode(coeffs, field_bits)
    return Case(payload, "NTT Domain Malformation", seed, "poly",
                list(range(n)), detail=f"style={style}, all coeffs > Q")


def signed_wrap_poly(rng: random.Random, q: int, n: int,
                     field_bits: int, seed: int) -> Case:
    """Inject signed 16/32-bit extremes into the packed byte stream.

    Targets integer overflow in polynomial add/sub where coefficients are held
    in int16_t / int32_t: values at INT_MIN/INT_MAX wrap on the next add.
    """
    coeffs = [rng.randrange(1 << field_bits) for _ in range(n)]
    payload = bytearray(L.byte_encode(coeffs, field_bits))
    width = rng.choice([2, 4])
    extremes = INT16_EXTREMES if width == 2 else INT32_EXTREMES
    k = rng.randint(1, max(1, len(payload) // (width * 4)))
    for _ in range(k):
        pat = rng.choice(extremes)
        off = rng.randrange(0, max(1, len(payload) - width))
        payload[off:off + width] = bytes(pat)
    return Case(bytes(payload), "Signed Vector Wrap-Around", seed, "poly",
                [], detail=f"{k}x int{width*8} extreme(s) injected")


# ---------------------------------------------------------------------------
# Ciphertext-domain mutations (structure preserved, values pushed to edges)
# ---------------------------------------------------------------------------

def ct_compressed_boundary(rng: random.Random, base_ct: bytes,
                           p: L.KemParams, seed: int) -> Case:
    """Decode a valid ct, push compressed coefficients to their field edges,
    re-encode. Exercises the decompress path with extremal-but-legal values."""
    u_polys, v_poly = L.decode_ciphertext(base_ct, p)
    du_edges = _q_boundary_values(p.q, p.du)
    dv_edges = _q_boundary_values(p.q, p.dv)
    touched = []
    for poly in u_polys:
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(p.n)
            poly[i] = rng.choice(du_edges) & ((1 << p.du) - 1)
            touched.append(i)
    for _ in range(rng.randint(1, 8)):
        i = rng.randrange(p.n)
        v_poly[i] = rng.choice(dv_edges) & ((1 << p.dv) - 1)
    payload = L.encode_ciphertext(u_polys, v_poly, p)
    return Case(payload, "Compressed-Coefficient Boundary", seed, "ct",
                sorted(set(touched)), detail="du/dv edge values")


def ct_havoc(rng: random.Random, base_ct: bytes, seed: int) -> Case:
    """Fixed-length havoc on the raw ciphertext bytes: interesting-byte sets,
    bit flips, signed extremes. Keeps length == len(base_ct)."""
    b = bytearray(base_ct)
    ops = rng.randint(1, 16)
    kinds = []
    for _ in range(ops):
        kind = rng.choice(["flip", "set", "int16", "int32"])
        kinds.append(kind)
        if kind == "flip":
            off = rng.randrange(len(b))
            b[off] ^= (1 << rng.randrange(8))
        elif kind == "set":
            off = rng.randrange(len(b))
            b[off] = rng.choice(INTERESTING_BYTES)
        elif kind == "int16" and len(b) >= 2:
            off = rng.randrange(len(b) - 1)
            b[off:off + 2] = bytes(rng.choice(INT16_EXTREMES))
        elif kind == "int32" and len(b) >= 4:
            off = rng.randrange(len(b) - 3)
            b[off:off + 4] = bytes(rng.choice(INT32_EXTREMES))
    return Case(bytes(b), "Ciphertext Havoc", seed, "ct", [],
                detail=f"{ops} ops")


# ---------------------------------------------------------------------------
# Strategy scheduler
# ---------------------------------------------------------------------------

class Scheduler:
    """Round-robins strategies appropriate to the chosen surface, producing an
    endless stream of reproducible Cases from a master seed."""

    def __init__(self, domain: str, params: L.KemParams,
                 base_ct: Optional[bytes], master_seed: int,
                 field_bits: int = 12):
        self.domain = domain
        self.p = params
        self.base_ct = base_ct
        self.field_bits = field_bits
        self._master = random.Random(master_seed)
        self._counter = 0

        if domain == "poly":
            self._strategies = [
                lambda rng, s: montgomery_boundary_poly(
                    rng, params.q, params.n, field_bits, s),
                lambda rng, s: ntt_domain_malform_poly(
                    rng, params.q, params.n, field_bits, s),
                lambda rng, s: signed_wrap_poly(
                    rng, params.q, params.n, field_bits, s),
            ]
        else:  # ct surface
            self._strategies = [
                lambda rng, s: ct_compressed_boundary(rng, base_ct, params, s),
                lambda rng, s: ct_havoc(rng, base_ct, s),
            ]

    def next_case(self) -> Case:
        seed = self._master.randrange(2 ** 63)
        strat = self._strategies[self._counter % len(self._strategies)]
        self._counter += 1
        rng = random.Random(seed)
        return strat(rng, seed)

    def replay(self, strategy_index: int, seed: int) -> Case:
        rng = random.Random(seed)
        return self._strategies[strategy_index](rng, seed)