# LatticeScope

Implementation-assurance tooling for post-quantum KEM/signature code. Two
modules audit **your own compiled** ML-KEM (Kyber) and ML-DSA (Dilithium)
builds for two of the defect classes that reference-correct lattice schemes
still ship with:

- **Module 1 — TVLA timing-leakage detector.** A cycle-accurate harness plus a
  streaming Welch's *t*-test that flags data-dependent execution time in
  decapsulation (and signature verification). This is the KyberSlash /
  non-constant-time-rejection family: correct math, leaky microarchitecture.
- **Module 2 — structure-aware algebraic / NTT fuzzer.** A grammar- and
  algebra-aware mutator plus a fork-isolated harness that finds memory-safety
  faults (SIGSEGV/SIGBUS/SIGFPE) in the unpacking and modular-arithmetic paths,
  and dumps a replayable crash corpus.

It targets code you control — a `.so` you built from the reference
implementation, PQClean, liboqs, or a vendor SDK. It does not attack a remote
party and needs no secret material it cannot mint from the target's own key
generation.

---

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Requirements: macOS/Linux, Python 3.9+, and a C compiler (`cc`/`clang`). The
timing shim in [cshim.c](cshim.c) and the demo target in [demo/vuln_kem.c](demo/vuln_kem.c)
are compiled at runtime from source so they always match the host ABI. The
project is verified with the commands below.

## Quick start — bundled demo (no external target needed)

```bash
./demo/build_demo.sh
python -m latticescope selftest
```

This compiles the demo targets [demo/vuln_kem.c](demo/vuln_kem.c) and
[demo/vuln_dsa.c](demo/vuln_dsa.c) into shared libraries and runs both modules
against them. The self-test should report a KEM decapsulation timing leak, a
fuzzing crash, and an ML-DSA verify timing leak, exiting successfully only when
all three planted bugs are detected.

## Live demo commands

### Module 1 — TVLA timing leak

```bash
python -m latticescope tvla \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --mode fixed-invalid --stop-on-leak
```

Then use the credibility check:

```bash
python -m latticescope tvla \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --mode fixed-random --iterations 40000
```

### Module 1 — ML-DSA signature-verify timing leak

```bash
python -m latticescope sign-tvla \
    --lib demo/libvuln_dsa.so --param ml-dsa-65 \
    --mode fixed-invalid --stop-on-leak
```

Class A is a fixed *invalid* signature (verify takes the reject path); Class B
is fresh *valid* signatures minted by the target's own signer. This probes
whether the reject path is constant-time relative to accept — the shape of a
non-constant-time ML-DSA verify (e.g. a rejection-sampling / hint-decode early
abort). Build the demo target with `cc -O2 -fPIC -shared demo/vuln_dsa.c -o
demo/libvuln_dsa.so`. Auditing a real target works exactly like `tvla`, with
`--sym-verify/--sym-keypair/--sym-sign` for non-standard symbol names.

### Module 2 — structure-aware fuzzer

Ciphertext surface:

```bash
python -m latticescope fuzz-lattice \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --surface ct --stop-on-first --out ./crashes
```

Poly surface (the “coefficient above $Q$ into the NTT” case):

```bash
python -m latticescope fuzz-lattice \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --surface poly --sym-fn poly_frombytes_demo \
    --in-len 384 --out-len 512 --stop-on-first --out ./crashes_poly
```

## Auditing a real target

```bash
# Timing leakage on decapsulation:
python -m latticescope tvla \
    --lib ./libmytarget.so --param ml-kem-768 --mode fixed-invalid

# Structure-aware fuzzing of the ciphertext-decapsulation surface:
python -m latticescope fuzz-lattice \
    --lib ./libmytarget.so --param ml-kem-768 --surface ct \
    --out ./crashes
```

### Expected target ABI

By default LatticeScope resolves the SUPERCOP convention:

```c
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_enc    (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_dec    (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);
```

It also auto-tries the `pqcrystals_kyber<n>_ref_*` and
`PQCLEAN_MLKEM<n>_CLEAN_*` naming schemes. If your build namespaces its symbols
differently, pass the exact exported names (inspect with `nm -D lib.so`):

```bash
python -m latticescope tvla --lib ./libmlkem768.so --param ml-kem-768 \
    --sym-keypair PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair \
    --sym-enc     PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc \
    --sym-dec     PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec
```

Parameter sets: `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`. Wire sizes are
derived from FIPS 203 and are used to mint valid inputs and to lay out
structure-preserving mutations.

---

## Module 1: TVLA

**Method.** Inputs are split into two classes and each is timed under identical
conditions, **interleaved within every batch** so slow drift (thermal,
frequency) hits both classes equally and cancels in the difference. A streaming
Welch's *t*-test tracks divergence; `|t| > 4.5` is the conventional flag for a
first-order, data-dependent (i.e. potentially exploitable) timing leak. The
tight loop lives in C (`cshim.ct_time_dec`) to keep CPython jitter out of the
signal.

**Classes.**

- `--mode fixed-invalid` (default): Class A is a *fixed* ciphertext corrupted so
  the FO re-encryption check fails and the implicit-rejection branch is taken;
  Class B is a stream of fresh valid ciphertexts from the target's own
  encapsulation. This directly probes whether the rejection path is
  constant-time relative to the success path.
- `--mode fixed-random`: Class A is one fixed valid ciphertext, Class B many
  random valid ones — a generic first-order test for any input dependence.

**Output.** Live `|t|` bar with a threshold marker, per-class mean cycles,
Δ-mean with a 95% confidence interval, *p*-value, and a verdict panel. On a
flagged leak the tool exits `2`.

### Measurement setup (read this before trusting numbers)

`|t|` is only as trustworthy as the measurement environment. For publishable
results:

- **Pin and isolate a core.** The tool sets CPU affinity and attempts to raise
  scheduling priority, but for clean data boot with `isolcpus=` (and ideally
  `nohz_full=`/`rcu_nocbs=`) and run on the isolated core with
  `taskset -c <core> --core <core>`.
- **Disable frequency scaling.** Set the `performance` governor and disable
  turbo/boost (`intel_pstate` no-turbo, or the equivalent), so cycle counts are
  not modulated by DVFS.
- **Understand the counter.** `RDTSCP` (and `CNTVCT_EL0`) count at a *constant
  reference frequency*, not retired core cycles. That is fine for TVLA — we
  compare two distributions measured the same way, and a real data-dependent
  branch shows up as a mean difference regardless — but do **not** read the raw
  numbers as core cycles. `read_cycles_overhead()` reports the counter's own
  read cost so you can sanity-check the noise floor.
- **macOS is coarse.** On macOS (including Apple Silicon) there is no
  userspace `CNTVCT_EL0` path, so the counter falls back to
  `mach_absolute_time` and reports **nanoseconds**, not cycles — the UI labels
  the unit accordingly. At ~1ns resolution, sub-microsecond leaks are not
  resolvable there; prefer x86_64 Linux for fine-grained timing work.
- **Sample enough.** `|t|` grows with `sqrt(n)`; a genuinely constant-time
  implementation should keep `|t|` bounded as iterations climb, while a leak
  diverges. Watch the trend, not a single snapshot. Use `--iterations` to cap
  and `--stop-on-leak` to halt on the first crossing.

A crossing is evidence of a data-dependent branch, not automatically a
practical attack; conversely, staying under 4.5 is not a constant-time proof.
Pair this with a static checker (e.g. `dudect`-style dynamic testing, `ctgrind`,
or `TIMECOP`/valgrind) for defense in depth.

---

## Module 2: structure-aware fuzzer

**Why structure-aware.** Generic byte-flippers waste cycles: they corrupt the
wire format before execution ever reaches the modular-arithmetic and NTT code.
These mutators target the *algebra* so malformation survives parsing:

- **Montgomery/Barrett boundary stress** — coefficients pinned on and just past
  the modulus (`Q`, `Q+1`, `2Q-1`, field extremes) to trip unhandled
  over-/under-reduction.
- **NTT domain malformation** — polynomials filled with un-reduced coefficients
  in `(Q, 2^field_bits)` so a subsequent butterfly/basemul can exceed the bound
  the next layer assumes.
- **Signed vector wrap-arounds** — `int16`/`int32` extremes injected into the
  packed stream to trigger integer overflow in polynomial add/sub.

**Two surfaces** (this distinction matters, so it is stated plainly):

- `--surface ct` fuzzes `crypto_kem_dec` with mutated **ciphertexts**. Because a
  ciphertext's compressed coefficients are bounded by `2^du`/`2^dv` (both `< Q`),
  ct-surface mutation is excellent at finding decoder, decompression and
  rejection-path bugs, but it does **not** reach *un-reduced coefficients above
  the modulus* — those are not representable in the ciphertext format.
- `--surface poly` fuzzes a named leaf directly (ABI
  `void fn(uint8_t *out, const uint8_t *in)`, e.g. a `poly_frombytes`-style
  unpacker). Here decoded coefficients *can* legitimately land in `(Q, 4095]`
  because reference Kyber does not reduce on `frombytes`, so these values flow
  straight into the NTT/basemul. This is the surface that actually exercises the
  "coefficient above `Q` into the NTT" condition.

  ```bash
  python -m latticescope fuzz-lattice --lib ./lib.so --param ml-kem-768 \
      --surface poly --sym-fn poly_frombytes --in-len 384 --out-len 512
  ```

**Isolation.** Crashes are caught by *process isolation*, not by trapping
`SIGSEGV` in-process — continuing a Python process after a ctypes call has
scribbled over memory is undefined behaviour. Each batch runs in a forked child;
a `MAP_SHARED` counter is bumped before every call, so when the child dies the
parent reads the counter and knows the **exact** offending case with no
bisection. `SIGALRM` (via `setitimer`) gives per-batch hang detection. Every
crash is replayed once in its own fork to confirm reproducibility.

**Sanitizer builds.** `SIGABRT` is already in the caught signal set, so a
target built with `-fsanitize=address,undefined` is handled transparently:
ASan/UBSan report-then-`abort()` on a defect, the fork-isolation harness
catches it exactly like a hard `SIGSEGV`/`SIGBUS`, and it's localized and
recorded the same way. This matters because not every memory bug produces an
immediate hard fault — a one-byte heap overflow that lands inside a mapped
page can silently corrupt adjacent memory with no signal at all, and only a
sanitizer build turns that into a catchable abort. On Linux, preload the
runtime as usual (`LD_PRELOAD=$(cc -fsanitize=address -print-file-name=libasan.so)`);
on macOS this requires `DYLD_INSERT_LIBRARIES`, which SIP may block for a
`dlopen`-loaded target — if interceptor installation fails, sanitize on Linux
or a CI runner instead.

**Crash corpus.** De-duplicated by `(signal, payload-prefix hash)` and written
to `--out` as a pair per unique crash:

- `crash_<SIGNAL>_<hash>.bin` — the raw payload for direct replay against the
  target.
- `crash_<SIGNAL>_<hash>.json` — strategy, seed, signal, touched coefficients,
  payload length and hex.

On any unique crash the tool exits `2`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Ran clean. For `tvla`/`fuzz-lattice`: no finding. For `selftest`: all three planted bugs were detected (success). |
| `2`  | A finding: `tvla` crossed the threshold, or `fuzz-lattice` recorded a unique crash. Useful as a CI gate. |
| `1`  | Usage / setup error (bad symbol, missing leaf args, demo source not found, compile failure). |

## The demo target (`demo/`)

[demo/vuln_kem.c](demo/vuln_kem.c) is **not** cryptography — it is a
 deliberately-flawed stand-in with the exact ML-KEM-768 ABI and two planted bugs
 so the modules have something real to find:

1. Decapsulation takes a **non-constant-time rejection branch** (data-dependent
   extra work) → Module 1 flags it.
2. That branch contains an **unchecked table index built from ciphertext
   bytes**, backed by a `PROT_NONE` guard page → Module 2 faults it. The
   `poly_frombytes_demo` leaf plants the analogous *un-reduced coefficient*
   index bug for the poly surface.

Valid ciphertexts take the accept branch, so the timing test never trips the
memory bug — only the fork-isolated fuzzer does. Build it standalone with
`demo/build_demo.sh`.

## Layout

```
latticescope/
  cli.py         argparse front end (tvla | sign-tvla | fuzz-lattice | selftest)
  target.py      ctypes binding of the target (symbol resolution, wrappers)
  cshim.c        timing counter and batched timing loops
  build_shim.py  runtime compiler + cache for the timing shim
  tvla.py        TVLA classes, interleaving, streaming test driver
  stats.py       Welford running stats, Welch's t, p-value, cropping
  mutators.py    algebra-aware coefficient/ciphertext mutators + scheduler
  fuzz.py        fork-isolated harness, crash localisation + triage
  lattice.py     FIPS 203/204 parameters and bit-exact serialization helpers
  ui.py          rich live UIs with plain-text fallbacks
  selftest.py    builds demo and drives both modules end-to-end
demo/
  vuln_kem.c     intentionally-flawed ML-KEM demonstration target
  vuln_dsa.c     intentionally-flawed ML-DSA verify target (timing leak)
  build_demo.sh  build script for the demo
```

## Known limitations / not yet implemented

Honest gaps:

- **No invariant-TSC check.** `cshim.c` reads RDTSCP/CNTVCT_EL0 and assumes
  it's a reliable constant-rate counter. It doesn't check the `constant_tsc`/
  `nonstop_tsc` CPUID bits, so a hypervisor that scales or traps the counter
  (common on cloud VMs) can silently produce untrustworthy `|t|` values with
  no warning.
- **ML-DSA `sign-tvla` `fixed-random` mode is limited by deterministic
  signing.** Signature verification timing *is* now auditable via the
  `sign-tvla` subcommand (fixed-invalid vs. fixed-random, mirroring the KEM
  path). But FIPS 204's default signing is deterministic, so `fixed-random`
  Class B produces identical signature bytes and only surfaces leakage that
  does not depend on the signature varying — the meaningful, default mode for
  a verify path is `fixed-invalid` (reject path vs. accept path). Fuzzing of
  the ML-DSA parsing surface is still not implemented.
- **The fuzzer is structure-aware, not coverage-guided.** Mutation strategies
  round-robin with no feedback from what code the target actually executed —
  no seed-corpus growth, no notion of "this input reached a new path." It's
  well-targeted at the algebraic bug classes it's built for, but it's not a
  substitute for a coverage-guided fuzzer (AFL++, libFuzzer) for general bug
  hunting.
- **No cross-run regression baseline.** Every `tvla` run is judged against
  the fixed `|t| > 4.5` cutoff in isolation. A build that goes from `|t|=0.5`
  to `|t|=3.9` between releases is trending toward a real leak, but nothing
  here persists prior-run stats to catch that before it crosses the line.

## What this is and isn't

- It finds **evidence** of timing and memory defects; it is not a proof of
  constant-timeness or memory safety. Absence of a finding is not a guarantee.
- The math routines in `lattice.py` are the public FIPS wire formats, present so
  the tool can build valid and precisely-malformed inputs — there is nothing
  secret or offensive in them.
- Results depend heavily on the measurement environment and on running against a
  build you control. Treat it as one instrument in an assurance pipeline
  alongside static analysis, formal constant-time verification, and
  code review.