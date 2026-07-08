# LatticeScope demo script (for DEF CON 34)

Run everything from `rust/`. Build once, then every section below is
copy-pasteable on its own.

```bash
cargo build --release
alias ls-run='cargo run --release --'
```

(Drop the alias and spell out `cargo run --release --` if you'd rather not
touch your shell — every command below assumes it exists.)

---

## 0. The 30-second version

```bash
ls-run demo --quick
```

Runs the fuzzer and TVLA back to back against the bundled mock target
(`examples/mock_pqc.c`, built automatically) and exits `2` — both planted
bugs found. This is the "does the tool even work" smoke test; everything
after this section shows the same two modules one piece at a time.

---

## 1. Module 1 — TVLA timing-leakage detector

Build the mock as a standalone `.so` once (the commands below need a
`--target path.so`, unlike `demo`, which builds its own copy):

```bash
make mock
```

**The leak** — `crypto_kem_dec`'s runtime depends on the ciphertext:

```bash
ls-run tvla --target ./examples/libmock_pqc.so --profile mock \
    --op dec --symbol crypto_kem_dec --iters 50000
```

Watch `|t|` climb well past the `4.5` threshold (typically >100 by the end)
and the verdict panel flip to `LEAK`.

**The negative control** — same computation, made input-independent:

```bash
ls-run tvla --target ./examples/libmock_pqc.so --profile mock \
    --op dec --symbol crypto_kem_dec_ct --iters 50000
```

`|t|` should stay under `4.5` the whole run — this is the point: the tool
doesn't cry wolf on constant-time code.

---

## 2. Module 2 — structure-aware fuzzer

**`deserialize` surface** — a raw 12-bit unpacker with two planted bugs
(coefficient `0xFFF` → SIGSEGV, coefficient `Q` → SIGFPE):

```bash
ls-run fuzz-lattice --target ./examples/libmock_pqc.so --profile mock \
    --surface deserialize --symbol poly_frombytes_vuln \
    --in-len 384 --out-len 256 --seed 42 --iters 20000
```

Crashes start appearing within the first couple hundred execs. Exits `2`.
With `--seed 42` this produces `crashes/crash_000002_SIGSEGV.json` (used
below), byte-identical every time you run it.

**`compressed` surface** — a real Kyber ciphertext shape (`c1||c2` at the
profile's `du`/`dv` widths) against a planted decompress bug:

```bash
ls-run fuzz-lattice --target ./examples/libmock_pqc.so --profile mock \
    --surface compressed --symbol decompress_ct_vuln --seed 42 --iters 3000
```

**Throughput: `--fork-server`** — same run, persistent-server backend
instead of one fork per exec (worth narrating: it's a modest, workload-
dependent win here, not an AFL-style jump — see README's "Throughput"
section for why):

```bash
ls-run fuzz-lattice --target ./examples/libmock_pqc.so --profile mock \
    --surface deserialize --symbol poly_frombytes_vuln \
    --in-len 384 --out-len 256 --seed 42 --iters 20000 --fork-server
```

Same crash set as the non-`--fork-server` run above — `crashes/` doesn't
grow, because these are the same `(signal, strategy)` pairs, already on disk.

**Crash triage: `replay`** — re-run one saved crash and confirm it still
reproduces:

```bash
ls-run replay --target ./examples/libmock_pqc.so \
    --crash crashes/crash_000002_SIGSEGV.json
```

Prints the recorded vs. observed signal side by side and exits `0` on a
match.

**CI ergonomics: `--json`** — machine-readable summary alongside the exit code:

```bash
ls-run fuzz-lattice --target ./examples/libmock_pqc.so --profile mock \
    --surface deserialize --symbol poly_frombytes_vuln \
    --in-len 384 --out-len 256 --seed 42 --iters 20000 --json
```

The JSON line lands on stderr (pass a path, e.g. `--json out.json`, to write
it to a file instead) and its `crashes`/`distinct` fields always agree with
the exit code.

---

## 3. Real-target validation (the "not just a toy" moment)

Fetches and builds real, audited PQClean implementations, then points both
modules at them:

```bash
make pqclean   # -> ./libmlkem768_pqclean.so, ./libmldsa65_pqclean.so
```

```bash
# TVLA on a real constant-time decapsulation: should NOT flag a leak
ls-run tvla --target ./libmlkem768_pqclean.so --profile kyber768 \
    --op dec --symbol PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec --iters 200000

# The fuzzer on a real deserialiser: should NOT crash
ls-run fuzz-lattice --target ./libmlkem768_pqclean.so --profile kyber768 \
    --surface deserialize --symbol PQCLEAN_MLKEM768_CLEAN_poly_frombytes \
    --in-len 384 --out-len 512 --iters 20000
```

Both come back clean — the real payoff of the whole demo: the same tool that
lit up like a Christmas tree on the mock stays quiet on hardened code. See
README's "Validation on real targets" for the `enc`/`verify` results too
(they *do* flag, and why that's expected rather than a miss).

---

## 4. Everything else

```bash
ls-run list       # known parameter profiles (sizes, symbols, du/dv)
ls-run --help     # full CLI reference
```
