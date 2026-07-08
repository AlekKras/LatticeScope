# LatticeScope (Rust Take)

This is my take on it with Rust. PRs welcome! 

A defensive auditing framework for **post-quantum cryptography implementations**.
It finds *implementation* flaws — the KyberSlash-class timing leaks and
boundary-triggered deserialiser bugs that live in code, not in the underlying
math. It is the same category of tool as `dudect` and the fuzzers behind
published PQC side-channel disclosures.

It does **not** recover keys, and it has **no remote surface**. You give it a
local shared object you are authorised to test; it times or fuzzes specific
exported symbols and reports what it finds.

Two modules:

| Module | Command | What it does |
| --- | --- | --- |
| Timing-leakage detection | `tvla` | A dudect/TVLA fixed-vs-random Welch t-test over the cycle counter. Flags input-dependent timing. |
| Structure-aware fuzzing | `fuzz-lattice` | Emits *structurally valid* lattice coefficient vectors and pushes them onto reduction/NTT/signed-wrap boundaries, each execution isolated in a forked child. |

This is a from-scratch Rust reimplementation of an earlier Python+C version.
The rewrite exists to fix three issues that stood between the tool and
real-world use (see [Why Write in Rust if Py would do](#why-write-in-rust-if-py-would-do)).

## Build

Requires a Rust toolchain (1.75+) and, for the bundled mock target only, a C
compiler.

```
cargo build --release
```

The single runtime dependency is `libc` (zero transitive dependencies,
maintained by the Rust project, and used by the standard library itself).
Everything else — argument parsing, the terminal UI, JSON emission, and the
cycle counter — is in-tree, so the whole tool is auditable in one read.

## Quick start

```
# See both modules light up on the bundled planted-bug target:
cargo run --release -- demo            # add --quick for a fast pass

# TVLA against a symbol in your own library:
cargo run --release -- tvla --target ./libyourpqc.so --profile kyber768 \
    --symbol crypto_kem_dec --core 3

# Structure-aware fuzzing of a deserialiser:
cargo run --release -- fuzz-lattice --target ./libyourpqc.so --profile kyber768 \
    --symbol poly_frombytes --surface deserialize --crash-dir crashes

# List known parameter profiles:
cargo run --release -- list
```

`tvla` exits `2` on a LEAK verdict; `fuzz-lattice` exits `2` if any crash was
found. Both are otherwise `0`, so they drop straight into CI. Add `--json
[path]` for a one-line, hand-rolled (no serde) summary on completion —
written to `path` if given, else stderr — so a CI step can read the verdict
without scraping the live-UI frame:

```bash
cargo run --release -- tvla --target ./libyourpqc.so --profile kyber768 \
    --symbol crypto_kem_dec --iters 200000 --json result.json
# {"tool":"tvla","target":"...","symbol":"crypto_kem_dec","op":"dec",
#  "verdict":"clean","t_raw":-1.30,"t_robust":-1.47,"n_a":...,"n_b":...,
#  "iters":200000,"exit_code":0}

cargo run --release -- fuzz-lattice --target ./libyourpqc.so --profile kyber768 \
    --surface deserialize --symbol poly_frombytes --json
# {"tool":"fuzz-lattice","target":"...","symbol":"poly_frombytes",
#  "surface":"deserialize","execs":...,"crashes":...,"distinct":...,
#  "signals":{"SIGSEGV":1,"SIGFPE":1},"timeouts":0,"exit_code":2}
```

`verdict`/`crashes` always agree with the exit code — the summary is written
from the same final state the exit code and last live-UI frame come from,
not recomputed separately.

## Module 1 — TVLA timing-leakage detection

The engine interleaves a **fixed** input class (A) with a **random** input
class (B) and times each call *in Rust*, reading the cycle counter immediately
around the indirect call into the target. No FFI-to-our-own-C and no
interpreter sit inside the measured window — only the target call does.

It reports two statistics:

* **`t(raw)`** — Welch's unequal-variance t over the whole run. This is the
  primary, calibrated statistic: for a single test at TVLA sample sizes,
  `|t| > 4.5` corresponds to a two-sided false-positive probability on the
  order of `1e-5`.
* **`t(robust)`** — the same test after discarding the extreme upper tail
  (preemptions, interrupts, migrations), at a small fixed set of crops. This is
  a *sensitivity* figure, reported honestly as such: a leak that only surfaces
  after cropping is still a leak, but a near-threshold tail-robust value on a
  noisy host is a signal to re-run pinned and quiesced — **not** a calibrated
  `1e-5` gate. The crop set is deliberately tiny so multiple-comparison
  inflation is negligible.

### Measurement quality matters

Timing measurements are only as good as the machine underneath them:

* Pin to a core with `--core N`.
* Disable turbo / fix the CPU frequency governor to `performance`; the counter
  reads the invariant TSC (see below), but frequency scaling still adds noise
  to the *work* being measured.
* Quiesce the box — no builds, no browser — while a run is in progress.
* Prefer more iterations (`--iters`) over trusting an early verdict.

## Module 2 — structure-aware lattice fuzzing

A blind byte fuzzer wastes almost all of its budget on inputs a packer rejects.
LatticeScope emits valid coefficient vectors and targets where lattice code
actually breaks:

* **random in-field baseline** — strictly `< q`; never emits a boundary value,
  so any crash is attributable to a specific mutation, not to random garbage;
* **Montgomery/Barrett boundary stress** — `q-1`, `q`, `q+1`, ...;
* **NTT domain malformation** — out-of-range clusters that violate
  coefficient-range assumptions an inverse-NTT may rely on;
* **signed wrap-around** — values that go negative when re-read as signed
  16/32-bit integers;
* **single boundary injection** — one coefficient set to one boundary value, the
  most surgical case.

Each execution runs in a **forked child**, so a memory-safety or arithmetic
fault kills only that child. Coefficients and the packed payload are prepared in
the parent *before* the fork, so the child does exactly one call into the target
and then exits.

### Surfaces: `deserialize`, `dec`, `compressed`

* `--surface deserialize` (default) — a 2-arg leaf `fn(out, in)` (e.g.
  `poly_frombytes`) fed a raw, `--field-bits`-wide packed coefficient vector.
  This is where un-reduced coefficients above the modulus actually reach the
  NTT/basemul path, since reference Kyber doesn't reduce on `frombytes`.
* `--surface dec` — the full 3-arg `crypto_kem_dec(ss, ct, sk)` with a mutated
  ciphertext against a fixed key. Ciphertext bytes are compressed (bounded by
  `2^du`/`2^dv`, both `< q`), so this surface is strong on decoder/rejection
  bugs but structurally can't reach an above-the-modulus coefficient.
* `--surface compressed` — builds an actual Kyber ciphertext shape: `k`
  `du`-bit-compressed `u` polynomials followed by one `dv`-bit-compressed `v`
  polynomial (FIPS 203's `c1 || c2`), each drawn from the same strategies
  above and run through `packing::compress` at the profile's `du`/`dv` width
  before packing. `k` is solved back out of `ct_len = du·k·n/8 + dv·n/8`
  rather than stored; `du`/`dv` are the only new `Profile` fields (FIPS 203
  Table 2: `kyber512`/`kyber768` use `du=10,dv=4`, `kyber1024` uses
  `du=11,dv=5`, `0/0` for signature profiles — checked by a
  `du_dv_reconstruct_ct_len` test). Targets a 2-arg decompress symbol, same
  ABI as `deserialize`.

  One honest caveat: compression is many-to-one, so on a `2^dv`- or
  `2^du`-slot compressed range, `n` coefficients per polynomial usually cover
  any given compressed value at least once *regardless of strategy* —
  including the "random in-field baseline". Unlike `deserialize`/`dec`, don't
  read a `compressed`-surface crash as attributable to one specific strategy;
  read it as "a boundary-adjacent compressed coefficient reaches this code
  path," which is still the property worth fuzzing.

### Crash artifacts and reproducibility

The first instance of each distinct `(signal, strategy)` pair is written to the
crash directory as a `.bin` (the raw payload) and a `.json` record containing
the terminating signal, the strategy, the RNG seed, the exec index, the
coefficient vector, the indices of out-of-range coefficients, and the payload
hex.

Every execution is deterministic in `(base_seed, exec_index)`: the same
`--seed` reproduces the same crashes, byte for byte, on replay. The JSON `note`
states plainly that the signal is observed via `waitpid`/`WIFSIGNALED` and that
**no register state is fabricated** — load the payload under a debugger or
enable a core dump for register-level detail.

### Crash triage: `replay`

```bash
latticescope replay --target ./libyourpqc.so --crash crashes/crash_000002_SIGFPE.json
```

Reads the `.bin` sitting next to the given `.json` (same stem) as the exact
original payload, resolves `func`/`kind` from the record, runs it once
through the target via the same `Reaper`, and prints the observed signal next
to the recorded one:

```
recorded     : SIGFPE
observed     : SIGFPE
MATCH — replay reproduced the recorded crash.
```

Exits `0` on a match, `2` on a mismatch — a mismatch means something is
genuinely worth looking at (a non-deterministic bug, or an environment
difference from the original run), not that replay itself failed.

One honest gap: a crash record stores the *per-exec* seed
(`exec_seed(base_seed, index)`), not the run's original `--seed`, so for a
`--surface dec` crash `replay` cannot regenerate byte-identical key material
— it derives a deterministic `sk` from the per-exec seed instead, which is
sufficient for `deserialize`/`compressed` crashes (no `sk` involved at all)
but may not exactly match the original `sk` bytes for a `dec`-surface crash
that happens to depend on key content.

### Throughput: `--fork-server`, and what it actually buys you

The default path forks fresh from the top-level process for every exec. Pass
`--fork-server` to instead fork one persistent server right after the target
is `dlopen`'d; the server then forks one worker per exec (crash isolation is
identical either way) and relays that worker's outcome back over a pipe,
reading the payload for that round from a `MAP_SHARED` region the parent
writes into before signalling "go". The server reaps its worker through the
exact same `Reaper` — same `sigtimedwait`/blocked-`SIGCHLD` discipline
(Invariant 2), not a second implementation of it — so the only new machinery
is the pipe/mmap handshake, not a new timeout path.

**Measured, not assumed** (this repo's sandbox: macOS/arm64; 20K execs,
`--seed 7`, default vs `--fork-server`, `poly_frombytes`-shaped surfaces):

| Target workload | Default | `--fork-server` | Δ |
| --- | --- | --- | --- |
| Light leaf fn (real PQClean `poly_frombytes`, ~µs/call) | 2.64–2.68K/s | 2.92–2.93K/s | **+~9–10%** |
| Heavy leaf fn (mock `crypto_kem_dec_ct`, fixed 96K-iteration loop) | ~1.31K/s | ~1.12K/s | **−~15%** |
| Crash-heavy (mock `poly_frombytes_vuln`, ~60% of execs signal) | 158/s | 162/s | ~none |

The honest reason it's a modest, workload-dependent win rather than an
AFL-style multi-x jump: classic fork-servers pay off by amortizing repeated
`execve` + ELF-load + constructor cost, and this tool never `execve`s at all —
the target is `dlopen`'d exactly once regardless of `--fork-server`, so that
cost was already zero on the default path. What a persistent server can still
save is forking from a small, static process instead of the (slightly larger,
still-growing) top-level one; that's a real but small effect, visible once a
call is cheap enough for fork overhead to be a meaningful share of the total
(the light-leaf-fn row), and swamped by one extra pipe round trip once the
call itself is expensive (the heavy-leaf-fn row). The crash-heavy row is flat
for a different reason entirely: on macOS, a hardware-fault signal
(`SIGSEGV`/`SIGFPE`) is intercepted by the OS crash reporter before `waitpid`
ever sees it, adding several milliseconds regardless of which process did the
forking — confirmed by isolated probes (`fork`+clean-`_exit`: ~2.6–3.7K/s;
`fork`+`SIGSEGV`: ~103/s). That tax is orthogonal to fork architecture and
not something either mode here can avoid.

Practical guidance: reach for `--fork-server` when fuzzing a cheap
deserialiser/leaf function (the common case for `--surface deserialize`);
don't expect it to help — it may mildly hurt — against an expensive call, and
don't expect it to change crash-heavy throughput on macOS at all.

**Reproducibility is unaffected.** The same `--seed 42` against the mock's
planted-bug deserialiser produces byte-identical crash artifacts with
`--fork-server` on and off — same filenames, same `.bin` MD5s, same JSON
fields other than the `--crash-dir` path baked into `path`. Payload generation
happens in the parent before either backend is asked to run it, so which
backend runs a call was never part of what determines its outcome.

## Why Write in Rust if Py would do

1. **The cropped-t statistic no longer over-claims.** The Python version
   computed the t-test at eight percentile crops and reported the maximum `|t|`
   while still advertising a per-test `p < 1e-5` guarantee — a
   multiple-comparison procedure sold as a calibrated one, biased toward false
   LEAK. Here the raw whole-stream Welch t is the calibrated primary; tail
   cropping is reduced to a small fixed set and reported separately as an
   explicitly-uncalibrated sensitivity figure. (You can watch this work in the
   `demo`: the constant-time control's tail-robust t sits slightly above its raw
   t but nowhere near the threshold.)

2. **The fork/timeout race is gone.** The Python version armed a `SIGALRM`
   handler that raised to interrupt `waitpid`; if a child exited within a hair
   of the deadline, the alarm could fire after the wait returned but before the
   timer was disarmed, and the stray signal escaped. This version blocks
   `SIGCHLD` up front and waits on it with `sigtimedwait`. A child that dies
   before we wait leaves the signal *pending* rather than lost; there is no
   handler and no timer to disarm, so there is no race.

3. **Honest nomenclature.** The counter unit reads `cycles (TSC)` because RDTSC
   reads the invariant TSC — reference cycles at the nominal base frequency, not
   core clocks under turbo/throttle (exactly what a differential test wants).
   What the Python version mislabelled a "reservoir" is a recency **window**,
   and is named that.

Rust also removes a class of problems structurally: there is no ctypes boundary
inside the timed window, integer-wrap semantics in the mutators are explicit
(`wrapping_*`), and the target handle's lifetime is tied to the resolved
function pointer.

## Validation on real targets

The demo proves the tooling lights up on planted bugs. The real acceptance
bar is the opposite: point both modules at an audited, hardened
implementation and confirm they *don't* fire.

Target: [PQClean](https://github.com/PQClean/PQClean)'s `clean` (portable C)
builds of **ML-KEM-768** and **ML-DSA-65**, built in-sandbox with `make
pqclean` (shallow, sparse clone of just those two scheme directories). The
existing `kyber768`/`dilithium3` profiles already carry PQClean's exact wire
sizes, so no new profile was needed — only the namespaced symbol names:

```bash
make pqclean   # -> ./libmlkem768_pqclean.so, ./libmldsa65_pqclean.so

cargo run --release -- tvla --target ./libmlkem768_pqclean.so --profile kyber768 \
    --op dec --symbol PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec

cargo run --release -- fuzz-lattice --target ./libmlkem768_pqclean.so --profile kyber768 \
    --surface deserialize --symbol PQCLEAN_MLKEM768_CLEAN_poly_frombytes \
    --in-len 384 --out-len 512
```

| Test | Symbol | Result |
| --- | --- | --- |
| `tvla --op dec` | `crypto_kem_dec` | **clean** — `t(raw) -1.30`, `t(robust) -1.47`, n=200K |
| `fuzz-lattice --surface deserialize` | `poly_frombytes` | **clean** — 20K execs, 0 crashes |
| `tvla --op enc` | `crypto_kem_enc` | flagged — `t(raw) -342.9` |
| `tvla --op verify` (ML-DSA-65) | `crypto_sign_verify` | flagged — `t(raw) -3.36`, `t(robust) -5.47` |

**`dec` and the deserialiser are the true negative controls, and both pass
clean** — a real constant-time decapsulation is not flagged, and a real
`poly_frombytes` does not crash under the same boundary mutations that break
the mock's planted unpacker.

**`enc` and `verify` also fire — expected, and not a PQClean bug or a tool
miss.** Neither symbol takes any secret-key input: every byte varied between
class A and B is public (a KEM public key; a signature), so a timing
difference there cannot leak anything an attacker doesn't already hold.
Traced to source rather than assumed:

- **`enc`**: `indcpa.c`'s `gen_matrix` expands the NTT matrix from `rho`, a
  seed carried inside the public key, via rejection sampling
  (`while (ctr < KYBER_N) { xof_squeezeblocks(...); ... }`). A fixed `rho`
  pins one fixed squeeze-round count; a fresh-random `rho` every call draws a
  fresh count each time. That mean gap between "always the same draw" and
  "a new draw every call" — not any secret dependence — is the `t(raw)=-343`
  signal.
- **`verify`**: `packing.c`'s `unpack_sig` rejects a malformed hint encoding
  the instant it sees one (`if (sig[OMEGA+i] < k || sig[OMEGA+i] > OMEGA)
  return 1;`, `OMEGA=55` for ML-DSA-65), and a uniformly random ~3.3KB
  signature fails that check almost immediately (~78% of the time on the
  very first check). The bound is verified *before* any index derived from
  it is used — confirmed safe by the 0-crash fuzz result above, just fast and
  input-shaped, which is also why verify runs at ~680K/s against dec/enc's
  ~35K/s. Note it crosses only on `t(robust)` (-5.47); per Invariant 1 above,
  `t(raw)` (-3.36) stays under the calibrated threshold.

Operational reading: `tvla --op dec` is the side-channel-relevant test for a
KEM, because decapsulation is the operation touching the long-term secret
key under attacker-chosen input. `--op enc`/`--op verify` report real,
honestly-measured timing variation, but over inputs with no secret content —
a flag there is a public-input-dependence measurement, not a KyberSlash-class
finding, unless your target's ABI actually threads secret material through
the varied argument.

Nothing in `fuzz.rs`, `tvla.rs`, `stats.rs`, or `sys.rs` changed for this
validation — only the target `.so` and profile/symbol arguments — so
reproducibility and the raw/robust separation carry over unmodified.

## Parameter profiles

`kyber512/768/1024` (ML-KEM, FIPS 203) and `dilithium2/3/5` (ML-DSA, FIPS 204),
plus `mock`. Sizes are the **final FIPS 204** values (e.g. ML-DSA-44 sk = 2560,
ML-DSA-87 sk = 4896), not the pre-standardisation round-3 CRYSTALS-Dilithium
numbers.

## The bundled mock target

`examples/mock_pqc.c` is a deliberately-vulnerable, non-cryptographic target so
the framework can be exercised end-to-end:

* `crypto_kem_dec` — decapsulation whose runtime depends on the ciphertext (a
  KyberSlash-style stand-in). TVLA should flag it.
* `crypto_kem_dec_ct` — the same computation made input-independent. TVLA should
  **not** flag it. Use it as a negative control.
* `poly_frombytes_vuln` — a 12-bit unpacker with two planted, boundary-triggered
  bugs: coefficient `0x0FFF` → NULL deref (SIGSEGV), coefficient `Q` (3329) →
  divide-by-zero (SIGFPE). The structure-aware mutators emit exactly these
  values; blind byte fuzzing rarely would.
* `decompress_ct_vuln` — a Kyber768-shaped (`du=10,dv=4,k=3`) compressed-
  ciphertext decompressor with two planted, boundary-triggered bugs, one per
  compressed part: a `du`-width (`c1`) coefficient `== 0` → NULL deref
  (SIGSEGV), a `dv`-width (`c2`) coefficient `== 0` → divide-by-zero (SIGFPE).
  Real `Compress_q` rounds values near `0` or `Q` to exactly `0`, so the
  `compressed`-surface payload's near-zero/near-`Q` boundary values land here
  reliably after compression.

It stays in C on purpose: Rust guards integer divide-by-zero, so an all-Rust
mock could not raise a genuine hardware SIGFPE.

## Scope and authorisation

Point this only at implementations you are authorised to test. It is built for
defenders auditing their own (or their vendors') PQC code before it ships.
