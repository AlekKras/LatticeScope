/*
 * vuln_kem.c -- an INTENTIONALLY FLAWED demonstration target for LatticeScope.
 *
 * This is NOT a cryptographic implementation. It is a stand-in with the exact
 * SUPERCOP/PQClean ABI and the exact ML-KEM-768 wire sizes, containing two
 * planted, textbook implementation bugs so the two LatticeScope modules have
 * something real to find at a live demo:
 *
 *   BUG 1 (timing -> Module 1 / TVLA):
 *     Decapsulation branches on whether an internal consistency check passes.
 *     The "implicit rejection" branch does a data-dependent amount of extra
 *     work, so it takes materially longer than the accept branch. This is the
 *     shape of the KyberSlash / non-constant-time-rejection family: the time
 *     to decapsulate depends on a property of the ciphertext. A fixed-vs-random
 *     TVLA run (fixed *invalid* ct vs. random *valid* cts) separates the two
 *     branches and Welch's t shoots past the 4.5 threshold.
 *
 *   BUG 2 (memory -> Module 2 / structure-aware fuzzer):
 *     On the rejection branch, a value read out of the ciphertext is used as an
 *     index into a one-page table with NO bounds check. A guard page sits
 *     immediately after the table (PROT_NONE), so any index past the page end
 *     faults deterministically with SIGSEGV -- the "out-of-bounds array access
 *     during unpacking" bug class. Ciphertexts produced by the target's own
 *     encapsulation keep this index small (in-bounds); the fuzzer's mutators
 *     drive it out of range.
 *
 * Because BUG 2 lives on the rejection branch, and valid ciphertexts (the ones
 * TVLA's Class B and warm-up use) take the accept branch, the TVLA module never
 * trips the memory bug -- only the fork-isolated fuzzer does. The one fixed
 * invalid ciphertext TVLA uses for Class A keeps the index in-bounds too (only
 * its last byte is flipped), so TVLA stays crash-free by construction.
 *
 * Build:
 *   cc -O2 -fPIC -shared vuln_kem.c -o libvuln_kem.so
 *
 * Exposes the default SUPERCOP names, so no --sym-* flags are needed:
 *   int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
 *   int crypto_kem_enc    (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
 *   int crypto_kem_dec    (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* ML-KEM-768 wire sizes (FIPS 203). */
#define CT_LEN 1088
#define PK_LEN 1184
#define SK_LEN 2400
#define SS_LEN 32

/* Offset of the 16-bit "probe" value inside the ciphertext. Lives in the u
 * region, away from the last byte that the TVLA corruptor flips. */
#define PROBE_OFF 100

/* ------------------------------------------------------------------ */
/* Tiny deterministic byte source so successive encapsulations differ. */
/* ------------------------------------------------------------------ */
static uint64_t g_state = 0x9e3779b97f4a7c15ULL;

static uint8_t next_byte(void)
{
    g_state = g_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint8_t)(g_state >> 56);
}

/* Rolling checksum over the first n bytes. The last ciphertext byte carries
 * this value as a validity tag; dec recomputes and compares. */
static uint8_t checksum(const uint8_t *b, size_t n)
{
    uint32_t s = 0;
    for (size_t i = 0; i < n; i++)
        s = s * 31u + b[i];
    return (uint8_t)(s ^ (s >> 8));
}

/* ------------------------------------------------------------------ */
/* One-page table with a PROT_NONE guard page immediately after it.   */
/* Any index >= page size reads into the guard page -> SIGSEGV.       */
/* ------------------------------------------------------------------ */
static uint8_t *g_table = NULL;
static size_t   g_page  = 0;

static void ensure_table(void)
{
    if (g_table)
        return;
    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0)
        pg = 4096;
    g_page = (size_t)pg;

    uint8_t *region = (uint8_t *)mmap(NULL, g_page * 2,
                                      PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        g_table = NULL;
        return;
    }
    /* Poison the second page so out-of-bounds indices fault hard. Place the
     * usable base 256 bytes before the guard: index 0..255 is in-bounds (a
     * valid ciphertext keeps this index <= 255), while index >= 256 -- which
     * requires the high probe byte to be nonzero, as only the fuzzer's
     * mutations make it -- lands on the guard page and faults. */
    mprotect(region + g_page, g_page, PROT_NONE);
    for (size_t i = 0; i < g_page; i++)
        region[i] = (uint8_t)(i * 7u + 1u);
    g_table = region + (g_page - 256);
}

/* ------------------------------------------------------------------ */
/* ABI                                                                */
/* ------------------------------------------------------------------ */

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk)
{
    for (int i = 0; i < PK_LEN; i++)
        pk[i] = next_byte();
    /* First 32 bytes act as the "secret" dec mixes into the shared secret. */
    for (int i = 0; i < SK_LEN; i++)
        sk[i] = next_byte();
    return 0;
}

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)pk;
    for (int i = 0; i < CT_LEN; i++)
        ct[i] = next_byte();

    /* Keep the probe index small so *valid* ciphertexts stay in-bounds even on
     * the rejection branch. High byte zeroed => index = low byte in [0,255]. */
    ct[PROBE_OFF + 1] = 0x00;

    /* Validity tag in the v-region (final byte). */
    ct[CT_LEN - 1] = checksum(ct, CT_LEN - 1);

    for (int i = 0; i < SS_LEN; i++)
        ss[i] = (uint8_t)(ct[i] ^ 0x5A);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Optional leaf for the fuzzer's "poly" surface.                     */
/*                                                                    */
/* ABI: void poly_frombytes_demo(uint8_t *out, const uint8_t *in)     */
/*   in  : 384 bytes = 256 coefficients, 12-bit packed (ML-KEM poly)  */
/*   out : 512 bytes = 256 int16 coefficients                         */
/*                                                                    */
/* Reference Kyber's poly_frombytes does NOT reduce coefficients, so a */
/* decoded value can legitimately be in (Q, 4095]. Here that UN-REDUCED */
/* value is used as a table index with a guard page placed exactly     */
/* after Q usable entries -- so any coefficient >= Q faults. This is    */
/* the "coefficient above the modulus flows unchecked into the NTT      */
/* path" bug, reachable only from the poly surface (not from a valid    */
/* ciphertext, whose compressed coefficients are all < 2^du < Q).      */
/* ------------------------------------------------------------------ */
static uint8_t *g_ntt_base = NULL;   /* points Q bytes before a guard page */

static void ensure_ntt_table(void)
{
    if (g_ntt_base)
        return;
    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0)
        pg = 4096;
    uint8_t *region = (uint8_t *)mmap(NULL, (size_t)pg * 2,
                                      PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED)
        return;
    mprotect(region + pg, (size_t)pg, PROT_NONE);
    for (long i = 0; i < pg; i++)
        region[i] = (uint8_t)i;
    /* Base such that index 0..Q-1 land in-page and index >= Q hit the guard. */
    g_ntt_base = region + ((size_t)pg - 3329);
}

void poly_frombytes_demo(uint8_t *out, const uint8_t *in)
{
    ensure_ntt_table();
    int16_t coeffs[256];
    /* Unpack 12-bit coefficients, LSB-first, WITHOUT reduction mod Q. */
    for (int i = 0; i < 128; i++) {
        uint16_t b0 = in[3 * i + 0];
        uint16_t b1 = in[3 * i + 1];
        uint16_t b2 = in[3 * i + 2];
        coeffs[2 * i + 0] = (int16_t)((b0 | (b1 << 8)) & 0x0FFF);
        coeffs[2 * i + 1] = (int16_t)(((b1 >> 4) | (b2 << 4)) & 0x0FFF);
    }
    volatile uint32_t sink = 0;
    for (int i = 0; i < 256; i++) {
        int c = coeffs[i];                 /* 0..4095, UN-REDUCED */
        if (g_ntt_base)
            sink += g_ntt_base[c];         /* faults when c >= Q (3329) */
        ((int16_t *)out)[i] = (int16_t)(coeffs[i]);
    }
    (void)sink;
}

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    volatile uint32_t acc = 0;
    uint8_t tag = checksum(ct, CT_LEN - 1);

    if (ct[CT_LEN - 1] == tag) {
        /* -------- ACCEPT branch: short, fixed work (constant-time-ish). ---- */
        for (int i = 0; i < 64; i++)
            acc += ct[i & 63];
    } else {
        /* -------- REJECT branch: the planted bugs live here. --------------- */
        ensure_table();

        /* BUG 2: unchecked index built from ciphertext bytes. */
        uint32_t idx = (uint32_t)ct[PROBE_OFF]
                     | ((uint32_t)ct[PROBE_OFF + 1] << 8);
        if (g_table) {
            volatile uint8_t x = g_table[idx];   /* faults when idx >= page */
            acc += x;
        }

        /* BUG 1: data-dependent extra work makes the reject path slow. */
        int reps = 24000 + (int)(ct[CT_LEN - 1] & 0x3F) * 256;
        for (int i = 0; i < reps; i++)
            acc += (uint32_t)ct[i % (CT_LEN - 1)] * 2654435761u;
    }

    for (int i = 0; i < SS_LEN; i++)
        ss[i] = (uint8_t)(acc + (uint32_t)i) ^ sk[i & (SK_LEN - 1)];
    return 0;
}