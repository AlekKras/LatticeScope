# Demo guide

This is created for the demo portion of DEFCON34 presentation. This project includes a bundled demo target that is intentionally flawed so you can try both detectors without needing your own library.

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

This builds the demo shared library from [demo/vuln_kem.c](demo/vuln_kem.c), runs the TVLA timing test, and then runs the structure-aware fuzzer.

### Expected outcome

- TVLA should flag the planted timing leak.
- The fuzzer should find the planted crash and write a crash artifact.
- The self-test exits with success when both detections are found.

## 3. Run the individual modules manually

First build the demo shared library:

```bash
./demo/build_demo.sh
```

The build script produces [demo/libvuln_kem.so](demo/libvuln_kem.so) and a convenience link at [libmlkem768.so](libmlkem768.so) for the commands below.

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

## 4. Troubleshooting

If the timing test does not trigger reliably on your machine:

- increase the iteration count with `--iterations`
- run the self-test again after a few minutes of idle CPU time
- avoid running on a heavily loaded system
- if possible, pin the process to a single core and disable turbo/boost
