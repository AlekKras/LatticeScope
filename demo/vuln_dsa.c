/*
 * vuln_dsa.c -- an INTENTIONALLY FLAWED demonstration target for LatticeScope.
 *
 * This is NOT a cryptographic implementation. It is a stand-in with the exact
 * SUPERCOP/PQClean detached-signature ABI and the ML-DSA-65 wire sizes,
 * containing ONE planted, textbook implementation bug so LatticeScope's
 * signature-timing module (`sign-tvla`) has something real to find:
 *
 *   BUG (timing -> Module 1 / TVLA on verify):
 *     Verification branches on whether the signature's validity tag matches.
 *     The reject branch does a data-dependent amount of extra work, so it
 *     takes materially longer than the accept branch. This is the shape of a
 *     non-constant-time ML-DSA verify -- e.g. a rejection-sampling / hint-decode
 *     path that early-aborts by a signature-dependent amount. A fixed-invalid
 *     TVLA run (fixed *invalid* sig vs. fresh *valid* sigs) separates the two
 *     branches and Welch's t shoots past the 4.5 threshold.
 *
 * There is deliberately NO memory bug here (unlike vuln_kem.c): this target
 * exercises the signature *timing* path only.
 *
 * Build:
 *   cc -O2 -fPIC -shared vuln_dsa.c -o libvuln_dsa.so
 *
 * Exposes the default SUPERCOP names, so no --sym-* flags are needed:
 *   int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
 *   int crypto_sign_signature(uint8_t *sig, size_t *siglen,
 *                             const uint8_t *m, size_t mlen, const uint8_t *sk);
 *   int crypto_sign_verify(const uint8_t *sig, size_t siglen,
 *                          const uint8_t *m, size_t mlen, const uint8_t *pk);
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ML-DSA-65 wire sizes (FIPS 204). */
#define SIG_LEN 3309
#define PK_LEN  1952
#define SK_LEN  4032

/* ------------------------------------------------------------------ */
/* Tiny deterministic byte source for reproducible "keys".            */
/* ------------------------------------------------------------------ */
static uint64_t g_state = 0x243f6a8885a308d3ULL;

static uint8_t next_byte(void)
{
    g_state = g_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint8_t)(g_state >> 56);
}

/* Validity tag binding the signature body, the message, and the public key.
 * verify recomputes it and compares against the last signature byte. */
static uint8_t tag(const uint8_t *sig, size_t n,
                   const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    uint32_t s = 0;
    for (size_t i = 0; i < n; i++)    s = s * 31u + sig[i];
    for (size_t i = 0; i < mlen; i++) s = s * 31u + m[i];
    for (size_t i = 0; i < PK_LEN; i++) s = s * 31u + pk[i];
    return (uint8_t)(s ^ (s >> 8) ^ (s >> 16));
}

/* ------------------------------------------------------------------ */
/* ABI                                                                */
/* ------------------------------------------------------------------ */

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    for (int i = 0; i < PK_LEN; i++)
        pk[i] = next_byte();
    /* The secret key carries a copy of the public key up front so the signer
     * can bind the validity tag to it (verify only sees the public key). */
    memcpy(sk, pk, PK_LEN);
    for (int i = PK_LEN; i < SK_LEN; i++)
        sk[i] = next_byte();
    return 0;
}

int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    const uint8_t *pk = sk;   /* pk lives at the front of sk (see keypair) */

    /* Deterministic "signature body" over the message + public key. */
    for (int i = 0; i < SIG_LEN - 1; i++) {
        uint8_t mb = mlen ? m[i % mlen] : 0;
        sig[i] = (uint8_t)(mb + (uint8_t)(i * 7u) + pk[i % PK_LEN]);
    }
    /* Validity tag in the last byte. */
    sig[SIG_LEN - 1] = tag(sig, SIG_LEN - 1, m, mlen, pk);

    if (siglen)
        *siglen = SIG_LEN;
    return 0;
}

int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    volatile uint32_t acc = 0;
    if (siglen < SIG_LEN)
        return -1;

    uint8_t t = tag(sig, SIG_LEN - 1, m, mlen, pk);

    if (sig[SIG_LEN - 1] == t) {
        /* -------- ACCEPT branch: short, fixed work. -------------------- */
        for (int i = 0; i < 64; i++)
            acc += sig[i & 63];
        (void)acc;
        return 0;
    }

    /* -------- REJECT branch: the planted timing bug lives here. --------
     * Data-dependent extra work makes the reject path slower by an amount
     * that depends on the signature -- exactly what a leaky verify does. */
    int reps = 24000 + (int)(sig[0] & 0x3F) * 256;
    for (int i = 0; i < reps; i++)
        acc += (uint32_t)sig[i % (SIG_LEN - 1)] * 2654435761u;
    (void)acc;
    return -1;
}
