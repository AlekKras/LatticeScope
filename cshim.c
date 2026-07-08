/*
 * cshim.c  --  LatticeScope low-overhead measurement core
 * ----------------------------------------------------------------------------
 * Compiled to a shared object (_ctshim.so) at runtime by build_shim.py and
 * driven from Python via ctypes. Keeping the tight measurement loop in C is
 * what lets us take TVLA-grade cycle measurements without CPython's per-call
 * bytecode-dispatch jitter dominating the signal.
 *
 * Two responsibilities:
 *   1. read_cycles()  -- a single serialized cycle-counter read, exported so
 *                        Python can bracket arbitrary calls when the batched
 *                        fast-paths below don't fit the target's ABI.
 *   2. ct_time_*()    -- batched loops that call a target crypto primitive N
 *                        times, timing each invocation individually and
 *                        writing the per-iteration cycle counts back to a
 *                        caller-owned buffer. These match the SUPERCOP/PQClean
 *                        ABI used by essentially every ML-KEM/ML-DSA build.
 *
 * IMPORTANT MEASUREMENT CAVEAT (see also README):
 *   On x86_64 we use RDTSCP, which counts at the CPU's *invariant* reference
 *   frequency, not retired core cycles. Under frequency scaling / turbo the
 *   absolute numbers are not "core cycles". That is fine for TVLA: the test
 *   only cares about the *difference in distribution* between two input
 *   classes measured under identical conditions. For clean results, pin a
 *   core, disable turbo, and set the performance governor (README has the
 *   exact commands).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------- */
/* Cycle counter                                                             */
/* ------------------------------------------------------------------------- */

#if defined(__x86_64__) || defined(__i386__)

/*
 * RDTSCP waits until all prior instructions have executed before reading the
 * TSC, giving us a well-defined "before" point. We follow with LFENCE so that
 * later instructions cannot be hoisted above the read. This is the standard
 * fencing pattern for microbenchmarking on x86.
 */
static inline uint64_t cs_cycles(void)
{
    uint32_t lo, hi, aux;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    __asm__ __volatile__("lfence" ::: "memory");
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

int cs_arch_is_x86(void) { return 1; }

#elif defined(__APPLE__)

#include <mach/mach_time.h>

/* macOS does not expose the Linux cntvct_el0 counter path, so use the native
 * monotonic timer with the proper conversion factor. This still gives a stable
 * ordering for TVLA-style comparisons. */
static inline uint64_t cs_cycles(void)
{
    static mach_timebase_info_data_t tb = {0};
    if (tb.denom == 0) {
        mach_timebase_info(&tb);
    }
    return mach_absolute_time() * tb.numer / tb.denom;
}

int cs_arch_is_x86(void) { return 0; }

#elif defined(__aarch64__)

/*
 * CNTVCT_EL0 is the EL0-readable virtual counter. Linux exposes it to
 * userspace by default. ISB serializes so the read reflects prior work. Note
 * the counter frequency (read from CNTFRQ_EL0) is typically far below the core
 * clock (often 24 MHz), so resolution is coarse -- adequate for gross timing
 * leaks, less so for single-cycle ones. Prefer x86 for fine-grained work.
 */
static inline uint64_t cs_cycles(void)
{
    uint64_t v;
    __asm__ __volatile__("isb; mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

int cs_arch_is_x86(void) { return 0; }

#else
#error "Unsupported architecture: need x86_64 or aarch64 for a cycle counter"
#endif

/* Exported single read for the generic Python-driven measurement path. */
uint64_t read_cycles(void) { return cs_cycles(); }

/* Rough measurement overhead of a back-to-back counter read (cycles). The
 * caller can subtract this as a constant; it cancels in TVLA anyway. */
uint64_t read_cycles_overhead(void)
{
    uint64_t best = (uint64_t)-1;
    for (int i = 0; i < 4096; i++) {
        uint64_t a = cs_cycles();
        uint64_t b = cs_cycles();
        uint64_t d = b - a;
        if (d < best) best = d;
    }
    return best;
}

/* ------------------------------------------------------------------------- */
/* Target ABI function-pointer typedefs (SUPERCOP / PQClean convention)      */
/* ------------------------------------------------------------------------- */

/* int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) */
typedef int (*kem_dec_fn)(uint8_t *, const uint8_t *, const uint8_t *);

/* int crypto_sign_verify(const uint8_t *sig, size_t siglen,
 *                        const uint8_t *m, size_t mlen, const uint8_t *pk) */
typedef int (*sig_verify_fn)(const uint8_t *, size_t,
                             const uint8_t *, size_t, const uint8_t *);

/* Generic single-input / single-output leaf, e.g. poly_frombytes-style:
 * void fn(uint8_t *out, const uint8_t *in)  (lengths are implicit/fixed) */
typedef void (*buf1_fn)(uint8_t *, const uint8_t *);

/* ------------------------------------------------------------------------- */
/* Batched timing: KEM decapsulation                                         */
/* ------------------------------------------------------------------------- */
/*
 * Times `n` decapsulations. `cts` is n contiguous ciphertexts each `ct_len`
 * bytes; the schedule (which class each index belongs to) is decided by the
 * Python caller so classes can be interleaved to cancel slow drift. Per-call
 * cycle counts are written to `out_cycles[i]`.
 *
 * `warmup` untimed calls are run first to settle caches / branch predictors.
 * Returns 0 on success, -1 on a bad argument.
 */
int ct_time_dec(void *fn_raw,
                const uint8_t *sk,
                const uint8_t *cts,
                size_t ct_len,
                size_t ss_len,
                size_t n,
                unsigned warmup,
                uint64_t *out_cycles)
{
    if (!fn_raw || !sk || !cts || !out_cycles || ct_len == 0 || ss_len == 0)
        return -1;

    kem_dec_fn fn = (kem_dec_fn)fn_raw;
    uint8_t *ss = (uint8_t *)malloc(ss_len);
    if (!ss) return -1;

    /* Warm-up on the first ciphertext (results discarded). */
    for (unsigned w = 0; w < warmup && n > 0; w++) {
        fn(ss, cts, sk);
    }

    for (size_t i = 0; i < n; i++) {
        const uint8_t *ct = cts + i * ct_len;
        uint64_t t0 = cs_cycles();
        fn(ss, ct, sk);
        uint64_t t1 = cs_cycles();
        out_cycles[i] = t1 - t0;
    }

    /* Touch ss so the compiler cannot elide the calls as dead. */
    volatile uint8_t sink = 0;
    for (size_t j = 0; j < ss_len; j++) sink ^= ss[j];
    (void)sink;

    free(ss);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Batched timing: signature verification                                    */
/* ------------------------------------------------------------------------- */
/*
 * Times `n` verifications of a *fixed* message against `n` signatures (each
 * `sig_len` bytes, contiguous in `sigs`). Useful for probing signature-parsing
 * / rejection timing in ML-DSA verify.
 */
int ct_time_verify(void *fn_raw,
                   const uint8_t *pk,
                   const uint8_t *m, size_t mlen,
                   const uint8_t *sigs, size_t sig_len,
                   size_t n,
                   unsigned warmup,
                   uint64_t *out_cycles)
{
    if (!fn_raw || !pk || !sigs || !out_cycles || sig_len == 0)
        return -1;

    sig_verify_fn fn = (sig_verify_fn)fn_raw;

    for (unsigned w = 0; w < warmup && n > 0; w++) {
        (void)fn(sigs, sig_len, m, mlen, pk);
    }

    for (size_t i = 0; i < n; i++) {
        const uint8_t *sig = sigs + i * sig_len;
        uint64_t t0 = cs_cycles();
        int rc = fn(sig, sig_len, m, mlen, pk);
        uint64_t t1 = cs_cycles();
        out_cycles[i] = t1 - t0;
        __asm__ __volatile__("" : : "r"(rc) : "memory"); /* keep rc live */
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Batched timing: generic single-buffer leaf                                */
/* ------------------------------------------------------------------------- */
/*
 * For low-level primitives such as poly_frombytes / polyvec_decompress that
 * take one input buffer and fill one output buffer of fixed sizes. `ins` holds
 * n contiguous inputs of `in_len`; a scratch output of `out_len` is reused.
 */
int ct_time_buf1(void *fn_raw,
                 const uint8_t *ins, size_t in_len,
                 size_t out_len,
                 size_t n,
                 unsigned warmup,
                 uint64_t *out_cycles)
{
    if (!fn_raw || !ins || !out_cycles || in_len == 0 || out_len == 0)
        return -1;

    buf1_fn fn = (buf1_fn)fn_raw;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) return -1;

    for (unsigned w = 0; w < warmup && n > 0; w++) fn(out, ins);

    for (size_t i = 0; i < n; i++) {
        const uint8_t *in = ins + i * in_len;
        uint64_t t0 = cs_cycles();
        fn(out, in);
        uint64_t t1 = cs_cycles();
        out_cycles[i] = t1 - t0;
    }

    volatile uint8_t sink = 0;
    for (size_t j = 0; j < out_len; j++) sink ^= out[j];
    (void)sink;

    free(out);
    return 0;
}