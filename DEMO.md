# Demo guide

This is intended for the demo portion of a DEF CON 34 presentation. This project includes a bundled demo target that is intentionally flawed so you can try both detectors without needing your own library.

## 1. Create and activate a virtual environment

From the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 2. Run the bundled self-test

```bash
python -m latticescope selftest
```

This builds the demo shared libraries from [demo/vuln_kem.c](demo/vuln_kem.c) and [demo/vuln_dsa.c](demo/vuln_dsa.c), runs the ML-KEM TVLA timing test, the structure-aware fuzzer, and the ML-DSA signature-verify timing test.

### Expected outcome

- TVLA (ML-KEM) should flag the planted decapsulation timing leak.
- The fuzzer should find the planted crash and write a crash artifact.
- TVLA (ML-DSA) should flag the planted signature-verify timing leak.
- The self-test exits with success when all three detections are found.

## 3. Run the individual modules manually

First build the demo shared library:

```bash
./demo/build_demo.sh
```

The build script produces [demo/libvuln_kem.so](demo/libvuln_kem.so), [demo/libvuln_dsa.so](demo/libvuln_dsa.so), and a convenience link at [libmlkem768.so](libmlkem768.so) for the commands below.

### Module 1 — TVLA timing leak (live)

Run the leak-finding demo:

```bash
python -m latticescope tvla \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --mode fixed-invalid --stop-on-leak
```

Watch the `|t|` bar shoot past the threshold marker and the verdict panel flip red. `--stop-on-leak` halts on the first crossing (otherwise it keeps sampling to the iteration cap). Exit code is `2` — a finding.

Then run the credibility check:

```bash
python -m latticescope tvla \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --mode fixed-random --iterations 40000
```

`|t|` stays under 4.5 and it exits `0`. The point to make is that the leak only exists between the rejection path and the accept path, so a test that only exercises valid ciphertexts correctly finds nothing.

### Module 1 — ML-DSA signature-verify timing leak (live)

Run the signature-verify leak demo:

```bash
python -m latticescope sign-tvla \
    --lib demo/libvuln_dsa.so --param ml-dsa-65 \
    --mode fixed-invalid --stop-on-leak
```

Same TVLA machinery, aimed at `crypto_sign_verify` instead of decapsulation. Class A is a fixed *invalid* signature (verify takes the reject path); Class B is fresh *valid* signatures the tool mints from the target's own keygen + signer. The `|t|` bar blows past the threshold and the verdict panel flips red — the shape of a non-constant-time verify (e.g. a rejection-sampling / hint-decode early abort). Exit code is `2`.

The credibility contrast here is `fixed-random`: because FIPS 204 signing is deterministic, valid signatures are byte-identical, so the mode has no signature variation to key on and `|t|` stays flat — the meaningful test for a verify path is `fixed-invalid` (reject vs. accept).

### Module 2 — structure-aware fuzzer, ciphertext surface (live)

```bash
python -m latticescope fuzz-lattice \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --surface ct --stop-on-first --out ./crashes
```

The exec/s counter climbs, then the red MEMORY VIOLATION panel appears with the signal, strategy, seed, and saved path. Exit code is `2`.

To inspect the crash record:

```bash
ls ./crashes/
cat ./crashes/crash_SIGSEGV_*.json
```

### Module 2 — poly surface (the “coefficient above Q into the NTT” money shot)

```bash
python -m latticescope fuzz-lattice \
    --lib demo/libvuln_kem.so --param ml-kem-768 \
    --surface poly --sym-fn poly_frombytes_demo \
    --in-len 384 --out-len 512 --stop-on-first --out ./crashes_poly
```

This crashes almost immediately on the first Montgomery-boundary case. The distinction to draw explicitly is that ciphertext-surface mutation cannot produce un-reduced coefficients above the modulus, while the poly surface reaches values in $(Q, 4095]$ that flow unchecked into the NTT.

## 4. Run the automated sign-tvla self-check

A standalone check builds [demo/vuln_dsa.c](demo/vuln_dsa.c) and asserts that the signature-timing module both flags the planted leak and stays quiet on a control run:

```bash
python3 test_sign_tvla.py
```

Expected output:

```
PASS: fixed-invalid flags the planted verify-timing leak
PASS: fixed-random control stays under the threshold

ALL SIGN-TVLA SELF-CHECKS PASSED
```

It needs no framework or virtualenv (it uses `cc` and the runtime-compiled timing shim). If `pytest` is installed, `python3 -m pytest -q test_sign_tvla.py` discovers the same two checks.

## 5. Troubleshooting

If the timing test does not trigger reliably on your machine:

- increase the iteration count with `--iterations`
- run the self-test again after a few minutes of idle CPU time
- avoid running on a heavily loaded system
- if possible, pin the process to a single core and disable turbo/boost
