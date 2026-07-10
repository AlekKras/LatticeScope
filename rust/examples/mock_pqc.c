/* =====================================================================
 * LatticeScope :: mock PQC target  (FOR DEMO / SELF-TEST ONLY)
 * ---------------------------------------------------------------------
 * This is NOT a cryptographic implementation. It exists so that the
 * LatticeScope framework can be exercised end-to-end without a real
 * library present, and so a DefCon audience can watch the tooling light
 * up on known-planted flaws before it is pointed at a real target.
 *
 * It exposes six things:
 *
 *   crypto_kem_dec        - a decapsulation whose runtime depends on the
 *                           ciphertext (a stand-in for a KyberSlash-style
 *                           data-dependent division/branch). TVLA should
 *                           flag this.
 *
 *   crypto_kem_dec_ct     - the same computation made input-independent
 *                           (constant work). TVLA should NOT flag this.
 *                           Use it as a negative control.
 *
 *   crypto_sign_verify    - a detached ML-DSA-65-shaped verify whose reject
 *                           path does signature-dependent extra work (the
 *                           accept path is short and fixed). The signature
 *                           side of the crypto_kem_dec leak. TVLA --op verify
 *                           should flag this.
 *
 *   poly_frombytes_vuln   - a 12-bit coefficient unpacker containing two
 *                           planted, boundary-triggered bugs:
 *                             * coefficient == 0xFFF  -> NULL deref (SIGSEGV)
 *                             * coefficient == Q(3329) -> div-by-zero (SIGFPE)
 *                           The structure-aware fuzzer emits exactly these
 *                           boundary values, so it will trip both quickly;
 *                           naive random byte fuzzing rarely would.
 *
 *   decompress_ct_vuln    - a Kyber768-shaped (du=10, dv=4, k=3) compressed-
 *                           ciphertext decompressor with two planted,
 *                           boundary-triggered bugs, one per compressed part:
 *                             * a du-width (c1) coefficient == 0 -> SIGSEGV
 *                             * a dv-width (c2) coefficient == 0 -> SIGFPE
 *                           Real Compress_q rounds values near 0 or Q to
 *                           exactly 0, so the `--surface compressed` payload
 *                           builder's near-zero/near-Q boundary values land
 *                           here reliably after compression.
 *
 *   sig_unpack_vuln       - the signature-side analogue of poly_frombytes_vuln:
 *                           a 23-bit (ML-DSA) coefficient unpacker with two
 *                           planted, boundary-triggered bugs:
 *                             * coefficient == 0x7FFFFF (2^23-1) -> SIGSEGV
 *                             * coefficient == Q (8380417)       -> SIGFPE
 *                           `--surface deserialize --profile dilithium3`
 *                           packs at 23 bits and emits exactly these values.
 *
 * Build:
 *   cc -O3 -fPIC -shared -o libmock_pqc.so mock_pqc.c
 * (-O3 is intentional: it mirrors the optimisation levels that introduce
 *  real-world timing leaks.)
 * ===================================================================== */

#include <stdint.h>
#include <stddef.h>

#define KYBER_N   256
#define KYBER_Q   3329
#define SS_LEN    32

/* volatile sink so the optimiser cannot delete the "work" loops */
static volatile uint64_t g_sink;

/* --- Module-1 fodder: leaky vs constant-time decapsulation --------- */

/* Runtime scales with popcount(ct[0..3]): a fixed ciphertext has a
 * fixed iteration count, random ciphertexts vary -> measurable,
 * ciphertext-dependent timing. This models an attacker-observable leak. */
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint64_t acc = 0;
    for (int i = 0; i < 64; i++) acc += (uint64_t)(ct[i % 32] ^ sk[i % 32]);

    unsigned pc = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b = ct[i];
        while (b) { pc += (b & 1u); b >>= 1; }
    }
    /* the data-dependent part */
    for (unsigned k = 0; k < pc * 6000u; k++)
        acc += (acc * 1103515245ULL + 12345ULL);

    g_sink += acc;
    for (int i = 0; i < SS_LEN; i++)
        ss[i] = (uint8_t)((acc >> ((i % 8) * 8)) & 0xFF) ^ sk[i % 32];
    return 0;
}

/* Same output distribution, input-independent iteration count. */
int crypto_kem_dec_ct(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint64_t acc = 0;
    for (int i = 0; i < 64; i++) acc += (uint64_t)(ct[i % 32] ^ sk[i % 32]);

    for (unsigned k = 0; k < 16u * 6000u; k++)   /* fixed 16, no ct dependence */
        acc += (acc * 1103515245ULL + 12345ULL);

    g_sink += acc;
    for (int i = 0; i < SS_LEN; i++)
        ss[i] = (uint8_t)((acc >> ((i % 8) * 8)) & 0xFF) ^ sk[i % 32];
    return 0;
}

/* --- Module-1 fodder: leaky detached-signature verify -------------- */

/* ML-DSA-65 detached-verify ABI (PQClean/SUPERCOP convention). This models a
 * non-constant-time verify: the accept path is short and input-independent,
 * while the reject path's runtime scales with the signature (popcount of the
 * first bytes -- the same data-dependent shape as crypto_kem_dec above, on the
 * signature side rather than the ciphertext side). A uniformly random ~3.3KB
 * signature effectively never matches the validity tag, so TVLA's fixed-vs-
 * random interleave stays on the reject path and measures its signature-
 * dependent timing -> flagged. See README "Known gaps" for why the accept
 * branch is unreachable under fixed-vs-random. */
#define DILITHIUM_SIG_LEN 3309
#define DILITHIUM_PK_LEN  1952

int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk) {
    uint64_t acc = 0;
    if (siglen < DILITHIUM_SIG_LEN)
        return -1;

    /* Validity tag over the signature body + message + public key; the last
     * signature byte must equal it to accept. Fixed work, no data-dependent
     * branch, so it adds equally to both TVLA classes. */
    uint32_t s = 0;
    for (int i = 0; i < DILITHIUM_SIG_LEN - 1; i++) s = s * 31u + sig[i];
    for (size_t i = 0; i < mlen; i++)               s = s * 31u + m[i];
    for (int i = 0; i < DILITHIUM_PK_LEN; i++)      s = s * 31u + pk[i];
    uint8_t t = (uint8_t)(s ^ (s >> 8) ^ (s >> 16));

    if (sig[DILITHIUM_SIG_LEN - 1] == t) {
        /* ACCEPT: short, fixed work (input-independent). */
        for (int i = 0; i < 64; i++) acc += sig[i & 63];
        g_sink += acc;
        return 0;
    }

    /* REJECT: signature-dependent extra work -- the planted timing leak. */
    unsigned pc = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b = sig[i];
        while (b) { pc += (b & 1u); b >>= 1; }
    }
    for (unsigned k = 0; k < pc * 6000u; k++)
        acc += (acc * 1103515245ULL + 12345ULL);

    g_sink += acc;
    return -1;
}

/* --- Module-2 fodder: boundary-triggered deserializer bugs --------- */

/* Unpacks 256 * 12-bit coefficients from 384 bytes (Kyber poly_frombytes
 * layout) and folds them into a 256-byte output. The two planted faults
 * fire on coefficient values that a structure-aware modulus-boundary
 * mutator is specifically designed to produce. */
int poly_frombytes_vuln(uint8_t *out, const uint8_t *in) {
    uint16_t coeffs[KYBER_N];
    for (int i = 0; i < KYBER_N / 2; i++) {
        coeffs[2 * i]     = (uint16_t)(( in[3 * i + 0]        |
                                        ((uint16_t)in[3 * i + 1] << 8)) & 0x0FFF);
        coeffs[2 * i + 1] = (uint16_t)(((in[3 * i + 1] >> 4)  |
                                        ((uint16_t)in[3 * i + 2] << 4)) & 0x0FFF);
    }

    for (int i = 0; i < KYBER_N; i++) {
        uint16_t c = coeffs[i];

        if (c == 0x0FFF) {               /* 12-bit max -> planted OOB / NULL deref */
            volatile int *p = (volatile int *)0;
            *p = (int)c;                 /* SIGSEGV */
        }
        if (c == KYBER_Q) {              /* exactly Q -> planted div-by-zero      */
            volatile int z = (int)c - KYBER_Q;   /* == 0 */
            g_sink += (uint64_t)((int)c / z);    /* SIGFPE */
        }

        out[i] = (uint8_t)(c & 0xFF);
    }
    return 0;
}

/* --- Module-2 fodder: planted compressed-ciphertext decompress bugs --- */

/* Kyber768-shaped compressed ciphertext: c1 = KYBER_K3 polys @ KYBER_DU bits
 * (C1_BYTES each) followed by c2 = 1 poly @ KYBER_DV bits (C2_BYTES),
 * matching FIPS 203's du=10/dv=4/k=3 for ML-KEM-768
 * (10*3*32 + 4*32 = 1088 = KYBER_CT_LEN). */
#define KYBER_DU  10
#define KYBER_DV  4
#define KYBER_K3  3
#define C1_BYTES  320 /* KYBER_N * KYBER_DU / 8 */
#define C2_BYTES  128 /* KYBER_N * KYBER_DV / 8 */

/* Generic little-endian d-bit unpack, matching packing::pack_bits' layout
 * (bit 0 of coefficient 0 -> bit 0 of byte 0). */
static uint32_t unpack_d(const uint8_t *buf, int idx, int d) {
    uint32_t bitpos = (uint32_t)idx * (uint32_t)d;
    uint32_t v = 0;
    for (int b = 0; b < d; b++) {
        uint32_t p = bitpos + (uint32_t)b;
        if (buf[p >> 3] & (1u << (p & 7))) {
            v |= (1u << b);
        }
    }
    return v;
}

/* Unpacks c1 || c2 and folds both into a 256-byte output, mirroring how a
 * real decapsulation decompresses u and v before the NTT/basemul step. The
 * two planted faults fire on the compressed-domain zero coefficient: real
 * Compress_q(x,d) rounds any x within a small margin of 0 or Q to exactly 0,
 * so the near-zero/near-Q boundary values the fuzzer's `compressed` surface
 * emits land here reliably. */
int decompress_ct_vuln(uint8_t *out, const uint8_t *ct) {
    for (int i = 0; i < KYBER_N; i++) {
        out[i] = 0;
    }
    for (int p = 0; p < KYBER_K3; p++) {
        const uint8_t *c1 = ct + p * C1_BYTES;
        for (int i = 0; i < KYBER_N; i++) {
            uint32_t v = unpack_d(c1, i, KYBER_DU);
            if (v == 0) {                        /* planted: NULL deref */
                volatile int *bad = (volatile int *)0;
                *bad = (int)v;                    /* SIGSEGV */
            }
            out[i] ^= (uint8_t)(v & 0xFF);
        }
    }
    const uint8_t *c2 = ct + KYBER_K3 * C1_BYTES;
    for (int i = 0; i < KYBER_N; i++) {
        uint32_t v = unpack_d(c2, i, KYBER_DV);
        if (v == 0) {                             /* planted: div-by-zero */
            volatile int z = (int)v;
            g_sink += (uint64_t)(100 / z);         /* SIGFPE */
        }
        out[i] ^= (uint8_t)(v & 0xFF);
    }
    return 0;
}

/* --- Module-2 fodder: planted signature-unpacker bugs -------------- */

/* ML-DSA-shaped 23-bit coefficient unpacker (256 coeffs from 736 bytes,
 * matching packing::pack_bits at poly_bits=23). The signature-side analogue
 * of poly_frombytes_vuln, reusing the same generic little-endian bit reader.
 * `--surface deserialize --profile dilithium3` packs at 23 bits and its
 * boundary mutators emit exactly the two planted trigger values. */
#define DILITHIUM_Q       8380417
#define DILITHIUM_FMAX23  0x7FFFFF   /* 2^23 - 1 */

int sig_unpack_vuln(uint8_t *out, const uint8_t *in) {
    for (int i = 0; i < KYBER_N; i++) {
        uint32_t c = unpack_d(in, i, 23);

        if (c == DILITHIUM_FMAX23) {         /* 23-bit max -> planted NULL deref */
            volatile int *p = (volatile int *)0;
            *p = (int)c;                     /* SIGSEGV */
        }
        if (c == DILITHIUM_Q) {              /* exactly Q -> planted div-by-zero */
            volatile int z = (int)c - DILITHIUM_Q;  /* == 0 */
            g_sink += (uint64_t)((int)c / z);        /* SIGFPE */
        }

        out[i] = (uint8_t)(c & 0xFF);
    }
    return 0;
}