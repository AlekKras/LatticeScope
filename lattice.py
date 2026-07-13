"""
lattice.py -- parameters and bit-exact (de)serialization for ML-KEM & ML-DSA.

The encode/decode/compress/decompress routines here follow FIPS 203 (ML-KEM)
and FIPS 204 (ML-DSA) so that ciphertexts / signatures we synthesize are
byte-identical to what a conformant implementation produces -- and so the
fuzzer's coefficient-domain mutations map deterministically onto the exact
bytes the target will parse.

Nothing here is secret or offensive: these are the public wire formats. They
exist so we can build *valid* inputs to compare against, and *precisely
malformed* inputs (a coefficient one above the modulus, a decoded value the
NTT layer will not expect) to probe how a given implementation handles the
edges of its own algebra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Shared ring constants
# ---------------------------------------------------------------------------

MLKEM_N = 256
MLKEM_Q = 3329          # prime modulus for ML-KEM (Kyber)

MLDSA_N = 256
MLDSA_Q = 8380417       # prime modulus for ML-DSA (Dilithium), 2^23 - 2^13 + 1


# ---------------------------------------------------------------------------
# Generic bit (de)serialization -- FIPS 203 ByteEncode/ByteDecode
# ---------------------------------------------------------------------------

def byte_encode(coeffs: List[int], d: int) -> bytes:
    """Pack a list of d-bit integers LSB-first into ceil(len*d/8) bytes.

    Mirrors FIPS 203 Algorithm 5 (ByteEncode_d). Values are masked to d bits;
    feeding a value >= 2^d is a legitimate stress case and simply wraps, which
    is exactly what a real encoder does with an out-of-range coefficient.
    """
    if not (1 <= d <= 32):
        raise ValueError("d must be in 1..32")
    mask = (1 << d) - 1
    acc = 0
    nbits = 0
    out = bytearray()
    for c in coeffs:
        acc |= (int(c) & mask) << nbits
        nbits += d
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


def byte_decode(data: bytes, d: int, n: int) -> List[int]:
    """Inverse of byte_encode: recover n d-bit integers (FIPS 203 Alg 6)."""
    if not (1 <= d <= 32):
        raise ValueError("d must be in 1..32")
    mask = (1 << d) - 1
    coeffs: List[int] = []
    acc = 0
    nbits = 0
    it = iter(data)
    for _ in range(n):
        while nbits < d:
            acc |= next(it) << nbits
            nbits += 8
        coeffs.append(acc & mask)
        acc >>= d
        nbits -= d
    return coeffs


# ---------------------------------------------------------------------------
# ML-KEM compression -- FIPS 203 Compress_d / Decompress_d
# ---------------------------------------------------------------------------

def compress(x: int, d: int, q: int = MLKEM_Q) -> int:
    """Compress_d(x) = round((2^d / q) * x) mod 2^d, with round-half-up."""
    x %= q
    num = (x << d) + (q // 2)      # +q/2 implements rounding
    return (num // q) & ((1 << d) - 1)


def decompress(y: int, d: int, q: int = MLKEM_Q) -> int:
    """Decompress_d(y) = round((q / 2^d) * y)."""
    num = q * y + (1 << (d - 1))
    return num >> d


# ---------------------------------------------------------------------------
# Scheme parameter sets
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KemParams:
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    n: int = MLKEM_N
    q: int = MLKEM_Q

    # Wire sizes, derived from the spec.
    @property
    def poly_bytes(self) -> int:          # 12-bit packed polynomial
        return self.n * 12 // 8           # 384

    @property
    def pk_bytes(self) -> int:
        return self.k * self.poly_bytes + 32   # t-hat polyvec + rho seed

    @property
    def sk_bytes(self) -> int:
        # s-hat polyvec || pk || H(pk) || z   (ML-KEM "full" secret key)
        return (self.k * self.poly_bytes
                + self.pk_bytes
                + 32   # H(pk)
                + 32)  # implicit-rejection z

    @property
    def ct_u_bytes(self) -> int:
        return self.k * (self.n * self.du // 8)

    @property
    def ct_v_bytes(self) -> int:
        return self.n * self.dv // 8

    @property
    def ct_bytes(self) -> int:
        return self.ct_u_bytes + self.ct_v_bytes

    @property
    def ss_bytes(self) -> int:
        return 32


@dataclass(frozen=True)
class SignParams:
    name: str
    k: int
    l: int
    sig_bytes: int
    pk_bytes: int
    sk_bytes: int
    n: int = MLDSA_N
    q: int = MLDSA_Q


# Standardized parameter sets (FIPS 203 / 204).
KEM_SETS = {
    "ml-kem-512":  KemParams("ml-kem-512",  k=2, eta1=3, eta2=2, du=10, dv=4),
    "ml-kem-768":  KemParams("ml-kem-768",  k=3, eta1=2, eta2=2, du=10, dv=4),
    "ml-kem-1024": KemParams("ml-kem-1024", k=4, eta1=2, eta2=2, du=11, dv=5),
}

SIGN_SETS = {
    "ml-dsa-44": SignParams("ml-dsa-44", k=4, l=4, sig_bytes=2420, pk_bytes=1312, sk_bytes=2560),
    "ml-dsa-65": SignParams("ml-dsa-65", k=6, l=5, sig_bytes=3309, pk_bytes=1952, sk_bytes=4032),
    "ml-dsa-87": SignParams("ml-dsa-87", k=8, l=7, sig_bytes=4627, pk_bytes=2592, sk_bytes=4896),
}


# ---------------------------------------------------------------------------
# Ciphertext (de)serialization for ML-KEM
# ---------------------------------------------------------------------------

def encode_ciphertext(u_polys: List[List[int]], v_poly: List[int],
                      p: KemParams) -> bytes:
    """Build a ciphertext from *already compressed* coefficient vectors.

    u_polys: k lists of n integers, each in [0, 2^du)
    v_poly : n integers in [0, 2^dv)
    Layout: ByteEncode_du(u_0)..ByteEncode_du(u_{k-1}) || ByteEncode_dv(v).
    """
    if len(u_polys) != p.k:
        raise ValueError(f"expected {p.k} u-polynomials, got {len(u_polys)}")
    out = bytearray()
    for poly in u_polys:
        if len(poly) != p.n:
            raise ValueError("u polynomial must have n coefficients")
        out += byte_encode(poly, p.du)
    if len(v_poly) != p.n:
        raise ValueError("v polynomial must have n coefficients")
    out += byte_encode(v_poly, p.dv)
    assert len(out) == p.ct_bytes, (len(out), p.ct_bytes)
    return bytes(out)


def decode_ciphertext(ct: bytes, p: KemParams):
    """Split a ciphertext back into (u_polys, v_poly) of compressed values."""
    if len(ct) != p.ct_bytes:
        raise ValueError(f"ciphertext must be {p.ct_bytes} bytes, got {len(ct)}")
    u_polys = []
    off = 0
    u_poly_bytes = p.n * p.du // 8
    for _ in range(p.k):
        chunk = ct[off:off + u_poly_bytes]
        u_polys.append(byte_decode(chunk, p.du, p.n))
        off += u_poly_bytes
    v_poly = byte_decode(ct[off:], p.dv, p.n)
    return u_polys, v_poly