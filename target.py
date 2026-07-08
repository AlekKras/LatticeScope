"""
target.py -- bind a compiled crypto implementation via ctypes.

LatticeScope audits *your* implementation: a shared object you built from the
reference code, PQClean, liboqs, a vendor SDK, etc. This module resolves the
standard SUPERCOP / PQClean function symbols, exposes both a raw function
address (for the C timing shim) and a safe Python-callable wrapper (for the
fork-isolated fuzzer), and uses the target's *own* keygen/encaps to mint valid
material so we never have to reimplement the scheme to get a baseline.

Default expected ABI (SUPERCOP convention):
    int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
    int crypto_kem_enc    (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int crypto_kem_dec    (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen, const uint8_t *pk);

If your build namespaces its symbols (e.g. PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec),
pass explicit names via the *_sym arguments or the CLI --sym-* flags.
"""

from __future__ import annotations

import ctypes
from typing import List, Optional, Tuple

from .lattice import KemParams, SignParams


u8 = ctypes.c_uint8
u8p = ctypes.POINTER(ctypes.c_uint8)


def _find_symbol(lib: ctypes.CDLL, explicit: Optional[str],
                 candidates: List[str]) -> Tuple[object, str]:
    """Return (func, resolved_name), trying an explicit name then candidates."""
    names = [explicit] if explicit else []
    names += candidates
    tried = []
    for name in names:
        if not name:
            continue
        tried.append(name)
        try:
            return getattr(lib, name), name
        except AttributeError:
            continue
    raise AttributeError(
        "Could not resolve required symbol. Tried: "
        + ", ".join(tried)
        + ".\nPass the exact exported name via the corresponding --sym-* flag "
        "(inspect with `nm -D <lib.so>`)."
    )


def _buf(n: int) -> ctypes.Array:
    return (u8 * n)()


class KemTarget:
    """Bound ML-KEM implementation."""

    def __init__(self, lib_path: str, params: KemParams,
                 keypair_sym: Optional[str] = None,
                 enc_sym: Optional[str] = None,
                 dec_sym: Optional[str] = None):
        self.params = params
        self.lib = ctypes.CDLL(lib_path)
        n = params.name.replace("ml-kem-", "")

        self._keypair, self.keypair_name = _find_symbol(
            self.lib, keypair_sym,
            ["crypto_kem_keypair",
             f"pqcrystals_kyber{n}_ref_keypair",
             f"PQCLEAN_MLKEM{n}_CLEAN_crypto_kem_keypair"])
        self._enc, self.enc_name = _find_symbol(
            self.lib, enc_sym,
            ["crypto_kem_enc",
             f"pqcrystals_kyber{n}_ref_enc",
             f"PQCLEAN_MLKEM{n}_CLEAN_crypto_kem_enc"])
        self._dec, self.dec_name = _find_symbol(
            self.lib, dec_sym,
            ["crypto_kem_dec",
             f"pqcrystals_kyber{n}_ref_dec",
             f"PQCLEAN_MLKEM{n}_CLEAN_crypto_kem_dec"])

        self._keypair.restype = ctypes.c_int
        self._keypair.argtypes = [u8p, u8p]
        self._enc.restype = ctypes.c_int
        self._enc.argtypes = [u8p, u8p, u8p]
        self._dec.restype = ctypes.c_int
        self._dec.argtypes = [u8p, u8p, u8p]

    # -- sizes -----------------------------------------------------------
    @property
    def ss_len(self) -> int: return self.params.ss_bytes
    @property
    def ct_len(self) -> int: return self.params.ct_bytes
    @property
    def pk_len(self) -> int: return self.params.pk_bytes
    @property
    def sk_len(self) -> int: return self.params.sk_bytes

    # -- raw address for the C shim -------------------------------------
    @property
    def dec_addr(self) -> int:
        return ctypes.cast(self._dec, ctypes.c_void_p).value

    # -- Python-callable wrappers ---------------------------------------
    def keypair(self) -> Tuple[bytes, bytes]:
        pk, sk = _buf(self.pk_len), _buf(self.sk_len)
        self._keypair(pk, sk)
        return bytes(pk), bytes(sk)

    def enc(self, pk: bytes) -> Tuple[bytes, bytes]:
        ct, ss = _buf(self.ct_len), _buf(self.ss_len)
        pk_buf = (u8 * self.pk_len)(*pk)
        self._enc(ct, ss, pk_buf)
        return bytes(ct), bytes(ss)

    def dec(self, ct: bytes, sk: bytes) -> bytes:
        """Direct decapsulation. Called inside the fuzzer's forked child, so a
        memory-unsafe target will fault the child, not this process."""
        ss = _buf(self.ss_len)
        ct_buf = (u8 * self.ct_len)(*ct[:self.ct_len].ljust(self.ct_len, b"\0"))
        sk_buf = (u8 * self.sk_len)(*sk)
        self._dec(ss, ct_buf, sk_buf)
        return bytes(ss)

    def dec_raw_ptr(self, ct_addr: int, sk_addr: int, ss_addr: int) -> int:
        """Call dec with pre-placed buffers (addresses). Used when the fuzzer
        wants a fixed sk/ss and only the ct bytes vary, avoiding re-marshalling
        the secret key each iteration."""
        return self._dec(
            ctypes.cast(ss_addr, u8p),
            ctypes.cast(ct_addr, u8p),
            ctypes.cast(sk_addr, u8p),
        )


class SignTarget:
    """Bound ML-DSA implementation (verify path only, for timing probes)."""

    def __init__(self, lib_path: str, params: SignParams,
                 verify_sym: Optional[str] = None):
        self.params = params
        self.lib = ctypes.CDLL(lib_path)
        n = params.name.replace("ml-dsa-", "")
        self._verify, self.verify_name = _find_symbol(
            self.lib, verify_sym,
            ["crypto_sign_verify",
             f"pqcrystals_dilithium{n}_ref_verify",
             f"PQCLEAN_MLDSA{n}_CLEAN_crypto_sign_verify"])
        self._verify.restype = ctypes.c_int
        self._verify.argtypes = [u8p, ctypes.c_size_t, u8p,
                                 ctypes.c_size_t, u8p]

    @property
    def sig_len(self) -> int: return self.params.sig_bytes
    @property
    def pk_len(self) -> int: return self.params.pk_bytes

    @property
    def verify_addr(self) -> int:
        return ctypes.cast(self._verify, ctypes.c_void_p).value

    def verify(self, sig: bytes, m: bytes, pk: bytes) -> int:
        sig_buf = (u8 * len(sig))(*sig)
        m_buf = (u8 * len(m))(*m) if m else None
        pk_buf = (u8 * self.pk_len)(*pk)
        return self._verify(sig_buf, len(sig), m_buf, len(m), pk_buf)